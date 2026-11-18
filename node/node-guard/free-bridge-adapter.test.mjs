import assert from "node:assert/strict";
import { test } from "node:test";
import { createFreeGuardHostAdapter } from "./free-bridge-adapter.mjs";

const at = Date.parse("2026-11-04T07:00:00Z");
const decision = { schema_version: 2, policy_id: "source-replay", application_id: "billing-api",
  identity_scope: "source_ip", identity_ref: "source_ip:8.8.8.8", source_ip: "8.8.8.8",
  reason_code: "replay_burst", action: "THROTTLE", hit_count: 3,
  observed_at: new Date(at).toISOString(), restriction_expires_at: new Date(at + 180_000).toISOString() };
const base = { enabled: true, applicationId: "billing-api", policyId: "source-replay",
  canActOnSource: () => true, now: () => at, ttlSeconds: 120 };

test("optional adapter is disabled until the operator enables a host bridge", async () => {
  const adapter = createFreeGuardHostAdapter();
  assert.deepEqual(await adapter.forward(decision), { status: "disabled" });
});

test("source-scoped decision reaches the authenticated bridge once with bounded TTL and no raw identity", async () => {
  const sent = [];
  const adapter = createFreeGuardHostAdapter({ ...base, bridge: { sendEvent: async (event) => {
    sent.push(event);
    return { status: "blocked" };
  } } });
  assert.equal((await adapter.forward(decision)).status, "blocked");
  assert.equal((await adapter.forward(decision)).status, "duplicate");
  assert.equal(sent.length, 1);
  assert.equal(sent[0].ttlSeconds, 120);
  assert.match(sent[0].evidenceHash, /^[a-f0-9]{64}$/);
  assert.equal(sent[0].eventId, sent[0].evidenceHash.slice(0, 32));
  assert.doesNotMatch(JSON.stringify(sent[0]), /secret|subject-1/);
});

test("identity-wide or cross-application decisions cannot become host bans", async () => {
  let called = 0;
  const adapter = createFreeGuardHostAdapter({ ...base, bridge: { sendEvent: async () => { called++; return { status: "blocked" }; } } });
  await assert.rejects(adapter.forward({ ...decision, identity_scope: "subject_id", identity_ref: "subject_id:abc" }), /source-scoped/);
  await assert.rejects(adapter.forward({ ...decision, application_id: "other-app" }), /source-scoped/);
  await assert.rejects(adapter.forward({ ...decision, policy_id: "another-policy" }), /source-scoped/);
  await assert.rejects(adapter.forward({ ...decision, source_ip: "127.0.0.1", identity_ref: "source_ip:127.0.0.1" }), /source-scoped/);
  await assert.rejects(adapter.forward({ ...decision, hit_count: 0 }), /source-scoped/);
  assert.equal(called, 0);
});

test("protected, observe-only, and too-short decisions never ask the agent to enforce", async () => {
  let called = 0;
  const bridge = { sendEvent: async () => { called++; return { status: "blocked" }; } };
  const protectedAdapter = createFreeGuardHostAdapter({ ...base, bridge, canActOnSource: () => false });
  assert.equal((await protectedAdapter.forward(decision)).status, "source_protected");
  const normal = createFreeGuardHostAdapter({ ...base, bridge });
  assert.equal((await normal.forward({ ...decision, action: "OBSERVE", restriction_expires_at: null })).status, "observe_only");
  assert.equal((await normal.forward({ ...decision, restriction_expires_at: new Date(at + 59_000).toISOString() })).status, "ttl_too_short");
  assert.equal(called, 0);
});

test("stale, future, and unbounded decisions cannot occupy the adapter or reach the agent", async () => {
  let called = 0;
  const adapter = createFreeGuardHostAdapter({ ...base, bridge: { sendEvent: async () => {
    called++;
    return { status: "blocked" };
  } } });
  await assert.rejects(adapter.forward({ ...decision,
    observed_at: new Date(at - 301_000).toISOString() }), /bounded free restriction/);
  await assert.rejects(adapter.forward({ ...decision,
    observed_at: new Date(at + 6_000).toISOString() }), /bounded free restriction/);
  await assert.rejects(adapter.forward({ ...decision,
    restriction_expires_at: new Date(at + 301_000).toISOString() }), /bounded free restriction/);
  assert.equal(called, 0);
  assert.equal((await adapter.forward(decision)).status, "blocked");
  assert.equal(called, 1);
});

test("agent outage reports failure while local decision remains independent", async () => {
  const results = [];
  const adapter = createFreeGuardHostAdapter({ ...base,
    bridge: { sendEvent: async () => { throw new Error("socket unavailable"); } },
    onResult: (result) => results.push(result) });
  assert.equal((await adapter.forward(decision)).status, "agent_unavailable");
  assert.equal(results[0].status, "agent_unavailable");
  assert.doesNotMatch(JSON.stringify(results), /socket unavailable/);
});

test("concurrent forwards of one decision cannot duplicate an agent request", async () => {
  let finish;
  const pending = new Promise((resolve) => { finish = resolve; });
  let called = 0;
  const adapter = createFreeGuardHostAdapter({ ...base, bridge: { sendEvent: async () => {
    called++;
    await pending;
    return { status: "observed" };
  } } });
  const first = adapter.forward(decision);
  const duplicate = adapter.forward(decision);
  finish();
  assert.equal((await first).status, "observed");
  assert.equal((await duplicate).status, "duplicate");
  assert.equal(called, 1);
});

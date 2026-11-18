import assert from "node:assert/strict";
import { test } from "node:test";
import { createHoneyMeshGuard } from "./index.mjs";

test("observe mode reports a threshold without blocking", async () => {
  let at = 1_000_000;
  const decisions = [];
  const guard = createHoneyMeshGuard({ mode: "observe", thresholds: { replay_burst: 2 }, now: () => at, onDecision: (decision) => decisions.push(decision) });
  assert.equal(guard.record({ sourceIp: "8.8.8.8", reasonCode: "replay_burst" }).action, "recorded");
  assert.equal(guard.record({ sourceIp: "8.8.8.8", reasonCode: "replay_burst" }).action, "observed");
  assert.equal(guard.isBlocked("8.8.8.8"), false);
  assert.deepEqual(guard.snapshot(), []);
  await Promise.resolve();
  assert.equal(decisions.length, 1);
  assert.equal(decisions[0].expiresAt, null);
  at += 61_000;
  assert.equal(guard.record({ sourceIp: "8.8.8.8", reasonCode: "replay_burst" }).action, "recorded");
});

test("enforce mode limits only the verified source, then releases and expires", () => {
  let at = 1_000_000;
  const guard = createHoneyMeshGuard({ mode: "enforce", thresholds: { invalid_signature_burst: 2 }, blockMs: 1_000, now: () => at, canActOnSource: (ip) => ip !== "1.1.1.1" });
  assert.equal(guard.record({ sourceIp: "8.8.8.8", reasonCode: "invalid_signature_burst" }).action, "recorded");
  assert.equal(guard.record({ sourceIp: "8.8.8.8", reasonCode: "invalid_signature_burst" }).action, "limit_armed");
  assert.equal(guard.isBlocked("8.8.8.8"), true);
  assert.equal(guard.isBlocked("9.9.9.9"), false);
  assert.equal(guard.record({ sourceIp: "1.1.1.1", reasonCode: "invalid_signature_burst" }).accepted, false);
  assert.equal(guard.snapshot().length, 1);
  assert.equal(guard.release("8.8.8.8"), 1);
  assert.equal(guard.isBlocked("8.8.8.8"), false);
  guard.record({ sourceIp: "8.8.8.8", reasonCode: "invalid_signature_burst" });
  guard.record({ sourceIp: "8.8.8.8", reasonCode: "invalid_signature_burst" });
  at += 1_001;
  assert.equal(guard.isBlocked("8.8.8.8"), false);
});

test("requires a verified-source policy for enforcement and rejects unsafe addresses", () => {
  assert.throws(() => createHoneyMeshGuard({ mode: "enforce" }), /canActOnSource/);
  const guard = createHoneyMeshGuard({ mode: "observe" });
  for (const sourceIp of ["127.0.0.1", "10.1.2.3", "100.64.1.1", "192.168.1.1", "198.18.1.1", "198.51.100.1", "::1", "2001:db8::1", "fc00::1", "::ffff:127.0.0.1", "not-an-ip"]) {
    assert.equal(guard.record({ sourceIp, reasonCode: "replay_burst" }).reason, "ineligible_source");
  }
  assert.equal(guard.record({ sourceIp: "8.8.8.8", reasonCode: "invented_attack" }).reason, "unknown_reason");
});

test("a changed allowlist stops an armed application limit immediately", () => {
  let allowed = true;
  const guard = createHoneyMeshGuard({ mode: "enforce", thresholds: { replay_burst: 2 }, canActOnSource: () => allowed });
  guard.record({ sourceIp: "8.8.8.8", reasonCode: "replay_burst" });
  guard.record({ sourceIp: "8.8.8.8", reasonCode: "replay_burst" });
  assert.equal(guard.isBlocked("8.8.8.8"), true);
  allowed = false;
  assert.equal(guard.isBlocked("8.8.8.8"), false);
  assert.deepEqual(guard.snapshot(), []);
  assert.equal(guard.record({ sourceIp: "8.8.8.8", reasonCode: "replay_burst" }).reason, "source_excluded");
});

test("does not allow single-event blocks or unbounded durations", () => {
  assert.throws(() => createHoneyMeshGuard({ thresholds: { replay_burst: 1 } }), /two observations/);
  assert.throws(() => createHoneyMeshGuard({ blockMs: 300_001 }), /safety limits/);
});

test("bounded state refuses new sources at capacity and recovers after expiry", () => {
  let at = 1_000_000;
  const guard = createHoneyMeshGuard({ mode: "observe", maxSources: 1, windowMs: 100, now: () => at });
  assert.equal(guard.record({ sourceIp: "8.8.8.8", reasonCode: "replay_burst" }).accepted, true);
  assert.equal(guard.record({ sourceIp: "9.9.9.9", reasonCode: "replay_burst" }).reason, "capacity_exhausted");
  at += 101;
  assert.equal(guard.record({ sourceIp: "9.9.9.9", reasonCode: "replay_burst" }).accepted, true);
});

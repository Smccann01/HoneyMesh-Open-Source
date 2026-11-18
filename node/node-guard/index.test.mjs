import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";
import { createHoneyMeshGuard, createNodeGuard } from "./index.mjs";
import { createGuardCore } from "./guard-core.mjs";
import { createAgentBridge } from "./bridge.mjs";

// Exercise the limiter with a controlled entitlement clock. Public callers use
// the embedded publisher keys and cannot supply this verifier.
const createLicensedGuard = (options) => createGuardCore({
  entitlement: { product: "node_guard", unit_id: "svc_test" }, unitId: "svc_test", ...options,
}, (document, product, unitId) => document?.unit_id === unitId && product === document?.product);

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

test("free standalone enforcement works without a license and retains source safeguards", () => {
  let at = 1_000_000;
  const guard = createNodeGuard({ mode: "enforce", thresholds: { replay_burst: 2 }, blockMs: 1_000,
    now: () => at, canActOnSource: (ip) => ip !== "1.1.1.1" });
  assert.equal(guard.record({ sourceIp: "8.8.8.8", reasonCode: "replay_burst" }).action, "recorded");
  assert.equal(guard.record({ sourceIp: "8.8.8.8", reasonCode: "replay_burst" }).action, "limit_armed");
  assert.equal(guard.isBlocked("8.8.8.8"), true);
  assert.deepEqual(guard.restriction("8.8.8.8"), { expiresAt: new Date(at + 1_000).toISOString(), retryAfterSeconds: 1 });
  assert.equal(guard.isBlocked("1.1.1.1"), false);
  assert.equal(guard.record({ sourceIp: "1.1.1.1", reasonCode: "replay_burst" }).reason, "source_excluded");
  assert.equal(guard.record({ sourceIp: "10.0.0.1", reasonCode: "replay_burst" }).reason, "ineligible_source");
  assert.equal(guard.snapshot().length, 1);
  at += 1_001;
  assert.equal(guard.isBlocked("8.8.8.8"), false);
  assert.equal(guard.restriction("8.8.8.8"), null);
  assert.deepEqual(guard.snapshot(), []);
});

test("agent outage cannot disable an independently armed free application limit", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "hm-guard-agent-outage-"));
  try {
    const bridge = createAgentBridge({ socketPath: path.join(directory, "absent.sock"),
      appId: "app_test_01", secret: "test-only-bridge-secret-with-32-plus-bytes" });
    let bridgeFailure;
    let attempted;
    const attemptedPromise = new Promise((resolve) => { attempted = resolve; });
    const guard = createNodeGuard({ mode: "enforce", thresholds: { replay_burst: 2 },
      canActOnSource: () => true,
      onDecision: async (decision) => {
        try {
          await bridge.sendEvent({ sourceIp: decision.sourceIp, reasonCode: decision.reasonCode,
            evidenceHash: "a".repeat(64), confidence: 90, ttlSeconds: 120 });
        } catch (error) {
          bridgeFailure = error;
        } finally {
          attempted();
        }
      } });
    guard.record({ sourceIp: "8.8.8.8", reasonCode: "replay_burst" });
    assert.equal(guard.record({ sourceIp: "8.8.8.8", reasonCode: "replay_burst" }).action, "limit_armed");
    await attemptedPromise;
    assert.match(bridgeFailure?.message, /ENOENT/);
    assert.equal(guard.isBlocked("8.8.8.8"), true);
    assert.equal(guard.release("8.8.8.8"), 1);
    assert.equal(guard.isBlocked("8.8.8.8"), false);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("free standalone enforcement still requires an explicit source policy", () => {
  assert.throws(() => createNodeGuard({ mode: "enforce" }), /canActOnSource/);
  assert.throws(() => createGuardCore({}, true), /entitlementValid/);
});

test("enforce mode limits only the verified source, then releases and expires", () => {
  let at = 1_000_000;
  const guard = createLicensedGuard({ mode: "enforce", thresholds: { invalid_signature_burst: 2 }, blockMs: 1_000, now: () => at, canActOnSource: (ip) => ip !== "1.1.1.1" });
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
  const freeGuard = createHoneyMeshGuard({ mode: "enforce", canActOnSource: () => true });
  assert.equal(freeGuard.record({ sourceIp: "8.8.8.8", reasonCode: "replay_burst" }).accepted, true);
  assert.throws(() => createLicensedGuard({ mode: "enforce" }), /canActOnSource/);
  const guard = createHoneyMeshGuard({ mode: "observe" });
  for (const sourceIp of ["127.0.0.1", "10.1.2.3", "100.64.1.1", "192.168.1.1", "198.18.1.1", "198.51.100.1", "::1", "100::1", "2001:db8::1", "fc00::1", "::ffff:127.0.0.1", "::ffff:8.8.8.8", "not-an-ip"]) {
    assert.equal(guard.record({ sourceIp, reasonCode: "replay_burst" }).reason, "ineligible_source");
  }
  assert.equal(guard.record({ sourceIp: "8.8.8.8", reasonCode: "invented_attack" }).reason, "unknown_reason");
});

test("a Node Pro host entitlement may include local Guard enforcement", () => {
  const guard = createLicensedGuard({ mode: "enforce", entitlement: { product: "node_pro", unit_id: "host_test" },
    unitId: "host_test", canActOnSource: () => true });
  assert.deepEqual(guard.snapshot(), []);
});

test("expired entitlement immediately stops application enforcement", () => {
  let valid = true;
  const guard = createGuardCore({ mode: "enforce", entitlement: { product: "node_guard", unit_id: "svc_test" }, unitId: "svc_test",
    thresholds: { replay_burst: 2 }, canActOnSource: () => true }, () => valid);
  guard.record({ sourceIp: "8.8.8.8", reasonCode: "replay_burst" });
  guard.record({ sourceIp: "8.8.8.8", reasonCode: "replay_burst" });
  assert.equal(guard.isBlocked("8.8.8.8"), true);
  valid = false;
  assert.equal(guard.isBlocked("8.8.8.8"), false);
  assert.deepEqual(guard.snapshot(), []);
  assert.equal(guard.record({ sourceIp: "8.8.8.8", reasonCode: "replay_burst" }).reason, "entitlement_invalid");
});

test("a changed allowlist stops an armed application limit immediately", () => {
  let allowed = true;
  const guard = createLicensedGuard({ mode: "enforce", thresholds: { replay_burst: 2 }, canActOnSource: () => allowed });
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

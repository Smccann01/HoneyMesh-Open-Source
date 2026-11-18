import { createHash } from "node:crypto";
import { isEligibleSource, REASON_CODES } from "./index.mjs";

const identifier = /^[a-z][a-z0-9._-]{1,63}$/;

/** Optional host bridge for decisions from the free SDK. */
export function createFreeGuardHostAdapter({ enabled = false, bridge, applicationId, policyId,
  canActOnSource, confidence = 90, ttlSeconds = 120, maxForwardedEvents = 10_000,
  onResult = () => {}, now = Date.now } = {}) {
  if (typeof enabled !== "boolean" || typeof onResult !== "function" || typeof now !== "function") {
    throw new TypeError("enabled and callbacks must have the expected types");
  }
  if (!enabled) return Object.freeze({ forward: async () => ({ status: "disabled" }) });
  if (!bridge || typeof bridge.sendEvent !== "function") throw new TypeError("enabled adapter requires an authenticated agent bridge");
  if (typeof applicationId !== "string" || !identifier.test(applicationId) ||
      typeof policyId !== "string" || !identifier.test(policyId)) {
    throw new TypeError("applicationId and policyId must be valid identifiers");
  }
  if (typeof canActOnSource !== "function") throw new TypeError("canActOnSource is required");
  if (!Number.isSafeInteger(confidence) || confidence < 80 || confidence > 100 ||
      !Number.isSafeInteger(ttlSeconds) || ttlSeconds < 60 || ttlSeconds > 300 ||
      !Number.isSafeInteger(maxForwardedEvents) || maxForwardedEvents < 1 || maxForwardedEvents > 10_000) {
    throw new RangeError("confidence, TTL, or event bound is outside the supported range");
  }
  const forwarded = new Map();
  const inFlight = new Set();

  async function report(result) {
    try { await onResult(Object.freeze(result)); } catch { /* Reporting cannot change local policy state. */ }
    return result;
  }

  async function forward(decision) {
    if (!decision || typeof decision !== "object" || decision.schema_version !== 2 ||
        decision.application_id !== applicationId || decision.policy_id !== policyId ||
        decision.identity_scope !== "source_ip" || !isEligibleSource(decision.source_ip) ||
        decision.identity_ref !== `source_ip:${decision.source_ip}` ||
        !REASON_CODES.includes(decision.reason_code) ||
        !["OBSERVE", "THROTTLE", "DENY"].includes(decision.action) ||
        !Number.isSafeInteger(decision.hit_count) || decision.hit_count < 1 ||
        typeof decision.observed_at !== "string" || !Number.isFinite(Date.parse(decision.observed_at))) {
      throw new TypeError("decision is not an eligible source-scoped v2 decision");
    }
    if (decision.action === "OBSERVE") return report({ status: "observe_only", policyId, sourceIp: decision.source_ip });
    let allowed = false;
    try { allowed = canActOnSource(decision.source_ip) === true; } catch { /* Protect on callback failure. */ }
    if (!allowed) return report({ status: "source_protected", policyId, sourceIp: decision.source_ip });
    const current = now();
    const observed = Date.parse(decision.observed_at);
    const expiry = Date.parse(decision.restriction_expires_at);
    if (!Number.isSafeInteger(current) || !Number.isFinite(expiry)) throw new TypeError("decision has no valid expiry");
    if (observed > current + 5_000 || observed < current - 300_000 ||
        expiry <= observed || expiry - observed > 300_000) {
      throw new TypeError("decision is outside the bounded free restriction window");
    }
    const boundedTtl = Math.min(ttlSeconds, Math.floor((expiry - current) / 1000));
    if (boundedTtl < 60) return report({ status: "ttl_too_short", policyId, sourceIp: decision.source_ip });
    const canonical = [decision.schema_version, decision.policy_id, decision.application_id,
      decision.identity_ref, decision.reason_code, decision.action, decision.observed_at,
      decision.restriction_expires_at, decision.hit_count].join("\0");
    const evidenceHash = createHash("sha256").update(canonical).digest("hex");
    const eventId = evidenceHash.slice(0, 32);
    for (const [id, until] of forwarded) if (until <= current) forwarded.delete(id);
    if (forwarded.has(eventId) || inFlight.has(eventId)) return report({ status: "duplicate", policyId, sourceIp: decision.source_ip, eventId });
    if (forwarded.size >= maxForwardedEvents) return report({ status: "capacity_exhausted", policyId, sourceIp: decision.source_ip });
    inFlight.add(eventId);
    try {
      const result = await bridge.sendEvent({ sourceIp: decision.source_ip, reasonCode: decision.reason_code,
        evidenceHash, confidence, ttlSeconds: boundedTtl, eventId });
      if (result?.status !== "observed" && result?.status !== "blocked") throw new Error("invalid agent result");
      forwarded.set(eventId, Math.min(expiry, current + boundedTtl * 1000));
      return report({ status: result.status, policyId, sourceIp: decision.source_ip, eventId });
    } catch {
      return report({ status: "agent_unavailable", policyId, sourceIp: decision.source_ip, eventId });
    } finally {
      inFlight.delete(eventId);
    }
  }

  return Object.freeze({ forward });
}

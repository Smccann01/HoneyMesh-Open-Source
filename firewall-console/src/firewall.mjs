import { randomUUID } from 'node:crypto';
import { isIP } from 'node:net';
import { isEligibleSource } from '@network-decode/node-guard';
import { createPolicyGuardV1 } from '@network-decode/node-guard/policy-runtime';
import { validateObservationV1, validatePolicyV1 } from '@network-decode/node-guard/policy';
import { comparePolicySimulation } from '@network-decode/node-guard/policy-diff';
import { replayPolicyV1 } from '@network-decode/node-guard/replay-policy';
import { createWebhookShield } from '@network-decode/node-guard/webhook-shield';

export const BASE_POLICY = Object.freeze({
  schema_version: 1,
  policy_id: 'login-abuse-v1',
  application_id: 'firewall-lab',
  mode: 'OBSERVE',
  route_id: 'auth.login',
  reason_code: 'authentication_failure',
  window_seconds: 60,
  threshold: 2,
  action: 'THROTTLE',
  restriction_seconds: 120,
});

/** An application-policy lab. It never writes a host firewall or kernel rule. */
export function createFirewallLab({ policy: inputPolicy = BASE_POLICY, webhookSecret,
  protectedSources = [], now = Date.now } = {}) {
  const policy = validatePolicyV1(inputPolicy);
  if (!Array.isArray(protectedSources) || protectedSources.length > 256 ||
      protectedSources.some((value) => !isEligibleSource(value))) {
    throw new TypeError('protectedSources must contain at most 256 eligible public IPs');
  }
  const canonicalProtected = protectedSources.map((value) => isIP(value) === 6
    ? new URL(`http://[${value}]/`).hostname.slice(1, -1) : value);
  const protectedSet = new Set(canonicalProtected);
  if (protectedSet.size !== canonicalProtected.length) throw new TypeError('protectedSources has duplicate IPs');
  const guard = createPolicyGuardV1({ policy, now,
    canActOnSource: (sourceIp) => !protectedSet.has(sourceIp),
    maxSources: 1_000, maxObservations: 5_000 });
  const shield = createWebhookShield({ secret: webhookSecret, now,
    toleranceSeconds: 300, maxBodyBytes: 65_536, maxEvents: 2_000 });
  const observations = [];
  const MAX_RECORDED = 1_000;

  function record(input) {
    const observation = validateObservationV1(input);
    const result = guard.record(observation);
    if (result.accepted) {
      observations.push(observation);
      if (observations.length > MAX_RECORDED) observations.shift();
    }
    return { ...result, restriction: guard.restriction(observation.source_ip) };
  }

  function syntheticAttempt(sourceIp) {
    return record({
      schema_version: 1, application_id: policy.application_id,
      event_id: randomUUID(), observed_at: new Date(now()).toISOString(),
      route_id: policy.route_id, reason_code: policy.reason_code,
      source_ip: sourceIp, protocol: 'HTTP',
    });
  }

  function acceptWebhook({ rawBody, timestamp, eventId, signature }) {
    const verified = shield.verify({ rawBody, timestamp, eventId, signature });
    if (!verified.accepted) return verified;
    let observation;
    try {
      observation = validateObservationV1(JSON.parse(Buffer.from(rawBody).toString('utf8')));
    } catch {
      return { accepted: false, reason: 'invalid_observation' };
    }
    if (observation.event_id !== eventId) return { accepted: false, reason: 'event_id_mismatch' };
    const result = record(observation);
    return { ...result, delivery_verified: true, event_id: eventId };
  }

  function orderedObservations() {
    return [...observations].sort((a, b) =>
      a.observed_at.localeCompare(b.observed_at) || a.event_id.localeCompare(b.event_id));
  }

  function review(proposedPolicy) {
    return comparePolicySimulation(policy, proposedPolicy, orderedObservations(),
      { at: new Date(now()).toISOString(), redactSources: true });
  }

  function replay(proposedPolicy = policy) {
    return replayPolicyV1({ policy: proposedPolicy, observations: orderedObservations(),
      at: new Date(now()).toISOString(), protectedSources: canonicalProtected, redactSources: true });
  }

  return Object.freeze({
    policy,
    syntheticAttempt,
    acceptWebhook,
    review,
    replay,
    probe: (sourceIp) => ({ restriction: guard.restriction(sourceIp), scope: 'synthetic_probe' }),
    release: (sourceIp) => guard.release(sourceIp),
    status: () => ({ policy, recorded_observations: observations.length,
      active_restrictions: guard.snapshot(), webhook: shield.status(),
      enforcement_scope: 'application_process_only', fixture_scope: 'synthetic_public_ip' }),
  });
}

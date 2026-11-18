import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac, randomUUID } from 'node:crypto';
import { request as httpRequest } from 'node:http';
import { BASE_POLICY, createFirewallLab } from '../src/firewall.mjs';
import { createFirewallServer } from '../src/server.mjs';

const instant = Date.parse('2026-11-04T10:00:20Z');
const secret = 'b'.repeat(64);
const source = '8.8.8.8';

test('OBSERVE records a trigger; proposed ENFORCE review and replay remain simulation-only', () => {
  const lab = createFirewallLab({ webhookSecret: secret, now: () => instant });
  assert.equal(lab.syntheticAttempt(source).action, 'recorded');
  assert.equal(lab.syntheticAttempt(source).action, 'OBSERVE');
  assert.equal(lab.probe(source).restriction, null);
  const proposed = { ...BASE_POLICY, mode: 'ENFORCE' };
  const review = lab.review(proposed);
  const replay = lab.replay(proposed);
  assert.equal(review.activation, 'none');
  assert.equal(review.source_redacted, true);
  assert.equal(replay.enforcement_scope, 'simulation_only');
  assert.equal(replay.active_restrictions.length, 1);
  assert.ok(!JSON.stringify({ review, replay }).includes(source));
  assert.equal(lab.probe(source).restriction, null);
});

test('ENFORCE applies a process-local restriction and operator release clears it', () => {
  const lab = createFirewallLab({ policy: { ...BASE_POLICY, mode: 'ENFORCE' },
    webhookSecret: secret, now: () => instant, protectedSources: ['9.9.9.9'] });
  assert.equal(lab.syntheticAttempt(source).action, 'recorded');
  assert.equal(lab.syntheticAttempt(source).action, 'THROTTLE');
  assert.equal(lab.probe(source).restriction.action, 'THROTTLE');
  assert.equal(lab.release(source), 1);
  assert.equal(lab.probe(source).restriction, null);
  assert.equal(lab.syntheticAttempt('9.9.9.9').accepted, false);
});

test('signed delivery is accepted once; bad signature, replay, and event mismatch are rejected', () => {
  const lab = createFirewallLab({ webhookSecret: secret, now: () => instant });
  const eventId = randomUUID();
  const observation = { schema_version: 1, application_id: 'firewall-lab', event_id: eventId,
    observed_at: new Date(instant).toISOString(), route_id: 'auth.login',
    reason_code: 'authentication_failure', source_ip: source, protocol: 'HTTP' };
  const rawBody = Buffer.from(JSON.stringify(observation));
  const timestamp = String(Math.floor(instant / 1_000));
  const signature = createHmac('sha256', secret).update('nodeguard-webhook-v1\n')
    .update(timestamp).update('\n').update(eventId).update('\n').update(rawBody).digest('hex');
  const input = { rawBody, timestamp, eventId, signature };
  assert.equal(lab.acceptWebhook({ ...input, signature: '0'.repeat(64) }).reason, 'invalid_signature');
  assert.equal(lab.acceptWebhook(input).accepted, true);
  assert.equal(lab.acceptWebhook(input).reason, 'duplicate_event');
  assert.equal(lab.status().recorded_observations, 1);
  const otherId = randomUUID();
  const mismatchSignature = createHmac('sha256', secret).update('nodeguard-webhook-v1\n')
    .update(timestamp).update('\n').update(otherId).update('\n').update(rawBody).digest('hex');
  assert.equal(lab.acceptWebhook({ rawBody, timestamp, eventId: otherId,
    signature: mismatchSignature }).reason, 'event_id_mismatch');
});

test('loopback HTTP dashboard keeps admin API authenticated and rejects cross-origin writes', async () => {
  const lab = createFirewallLab({ policy: { ...BASE_POLICY, mode: 'ENFORCE' }, webhookSecret: secret });
  const adminToken = 'a'.repeat(64);
  const server = createFirewallServer({ lab, adminToken, html: '<h1>lab</h1>', script: '' });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    assert.equal((await fetch(`${base}/health`)).status, 200);
    const wrongHostStatus = await new Promise((resolve, reject) => {
      const probe = httpRequest(`${base}/health`, { headers: { host: 'unexpected.example' } }, (response) => {
        response.resume();
        resolve(response.statusCode);
      });
      probe.on('error', reject);
      probe.end();
    });
    assert.equal(wrongHostStatus, 403);
    assert.equal((await fetch(`${base}/api/status`)).status, 401);
    const headers = { authorization: `Bearer ${adminToken}`, 'content-type': 'application/json' };
    const post = (path, body, extra = {}) => fetch(`${base}${path}`, {
      method: 'POST', headers: { ...headers, ...extra }, body: JSON.stringify(body),
    });
    assert.equal((await post('/api/lab/attempt', { source_ip: source },
      { origin: 'https://untrusted.example' })).status, 403);
    assert.equal((await post('/api/lab/attempt', { source_ip: source })).status, 200);
    assert.equal((await post('/api/lab/attempt', { source_ip: source })).status, 200);
    const probe = await (await post('/api/lab/probe', { source_ip: source })).json();
    assert.equal(probe.restriction.action, 'THROTTLE');
    assert.equal((await post('/api/lab/release', { source_ip: source })).status, 200);
    assert.equal((await post('/webhooks/observation', { foo: 'bar' })).status, 401);
  } finally {
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
});

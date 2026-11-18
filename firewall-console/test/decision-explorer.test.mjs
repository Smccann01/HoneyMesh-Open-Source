import test from 'node:test';
import assert from 'node:assert/strict';
import { canonicalAddress, explainHostDecision } from '../src/decision-explorer.mjs';
import { createFirewallLab } from '../src/firewall.mjs';
import { createFirewallServer } from '../src/server.mjs';

const sampledAt = '2026-11-06T12:00:00.000Z';
const grant = { IP: '2001:db8::1', Owner: { Kind: 'local', ID: 'firewall-console:123' },
  Reason: 'operator review', PolicyVersion: 'rc4-runtime-v1', ExpiresAt: '2026-11-06T12:05:00Z' };

test('decision explanation distinguishes confirmed, pending, override, and absent state', () => {
  assert.equal(canonicalAddress('2001:0db8::1'), '2001:db8::1');
  assert.equal(canonicalAddress('::ffff:8.8.8.8'), '8.8.8.8');
  assert.equal(canonicalAddress('localhost'), null);
  const snapshot = [{ State: { IP: '2001:db8::1', KernelApplied: true }, Grants: [grant] }];
  const applied = explainHostDecision('2001:0db8::1', snapshot, { mode: 'ENFORCE', xdp_attached: true }, { ipv6: { packets: 42 } }, sampledAt);
  assert.equal(applied.outcome, 'kernel_block_confirmed');
  assert.equal(applied.grants[0].policy_version, 'rc4-runtime-v1');
  assert.equal(applied.global_counters_are_per_source, false);
  snapshot[0].State.KernelApplied = false;
  assert.equal(explainHostDecision('2001:db8::1', snapshot, null, null, sampledAt).outcome, 'grant_pending_or_not_applied');
  snapshot[0].State.OverrideExpiresAt = '2026-11-06T12:01:00Z';
  assert.equal(explainHostDecision('2001:db8::1', snapshot, null, null, sampledAt).outcome, 'override_active');
  assert.equal(explainHostDecision('8.8.8.8', snapshot, null, null, sampledAt).outcome, 'no_active_grant');
});

test('host decision API requires agent access and keeps failed optional reads explicit', async () => {
  const labToken = 'l'.repeat(64);
  const agentToken = 'a'.repeat(64);
  const control = {
    authenticate: async (token) => { if (token !== agentToken) throw new Error('bad token'); },
    grants: async () => [{ State: { IP: '8.8.8.8', KernelApplied: false, LastError: 'retry pending' },
      Grants: [{ IP: '8.8.8.8', Owner: { Kind: 'local', ID: 'operator' }, Reason: 'test', ExpiresAt: '2026-11-06T12:05:00Z' }] }],
    contract: async () => { throw new Error('old agent'); },
    counters: async () => { throw new Error('counters unavailable'); },
  };
  const server = createFirewallServer({ lab: createFirewallLab({ webhookSecret: 's'.repeat(64) }),
    adminToken: labToken, html: '', script: '', agentControl: control });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    assert.equal((await fetch(`${base}/api/host/decision?ip=8.8.8.8`)).status, 401);
    const login = await fetch(`${base}/api/session`, { method: 'POST', headers: { origin: base, 'content-type': 'application/json' },
      body: JSON.stringify({ token: labToken }) });
    const labCookie = login.headers.get('set-cookie').split(';')[0];
    assert.equal((await fetch(`${base}/api/host/decision?ip=8.8.8.8`, { headers: { cookie: labCookie } })).status, 401);
    const host = await fetch(`${base}/api/host/session`, { method: 'POST', headers: { cookie: labCookie, origin: base, 'content-type': 'application/json' },
      body: JSON.stringify({ token: agentToken }) });
    const cookie = `${labCookie}; ${host.headers.get('set-cookie').split(';')[0]}`;
    assert.equal((await fetch(`${base}/api/host/decision?ip=not-an-ip`, { headers: { cookie } })).status, 400);
    assert.equal((await fetch(`${base}/api/host/history?ip=8.8.8.8`, { headers: { cookie } })).status, 409);
    const oldPreview = await fetch(`${base}/api/host/preview`, { method: 'POST',
      headers: { cookie, origin: base, 'content-type': 'application/json' }, body: JSON.stringify({ ip: '8.8.8.8', ttl_seconds: 60 }) });
    assert.equal(oldPreview.status, 409);
    const response = await fetch(`${base}/api/host/decision?ip=8.8.8.8`, { headers: { cookie } });
    assert.equal(response.status, 200);
    const decision = await response.json();
    assert.equal(decision.outcome, 'grant_pending_or_not_applied');
    assert.equal(decision.kernel_applied, false);
    assert.equal(decision.last_reconciliation_error, 'retry pending');
    assert.equal(decision.host_mode, null);
    assert.equal(decision.global_xdp_drop_totals, null);
    assert.equal(JSON.stringify(decision).includes(agentToken), false);
  } finally { await new Promise((resolve) => server.close(resolve)); }
});

test('new agent decision, preview, and history remain read-only when host writes are closed', async () => {
  const labToken = 'l'.repeat(64);
  const agentToken = 'a'.repeat(64);
  let writes = 0;
  const control = {
    authenticate: async () => {},
    decision: async () => ({ ip: '8.8.8.8', sampled_at: '2026-11-06T12:00:00Z', outcome: 'kernel_block_reported',
      mode: 'ENFORCE', xdp_attached: true, kernel_applied: true, grants: [], scope: 'exact source', observation_limit: 'not packet history' }),
    history: async () => ({ ip: '8.8.8.8', events: [{ operation: 'apply', result: 'success' }] }),
    preview: async () => ({ blockers: [], immediate_kernel_effect_possible: true, simulation: 'no packet replay' }),
    counters: async () => ({ ipv4: { packets: 9 } }),
    ban: async () => { writes++; },
  };
  const server = createFirewallServer({ lab: createFirewallLab({ webhookSecret: 's'.repeat(64) }),
    adminToken: labToken, html: '', script: '', agentControl: control, hostActionsEnabled: false });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    const login = await fetch(`${base}/api/session`, { method: 'POST', headers: { origin: base, 'content-type': 'application/json' },
      body: JSON.stringify({ token: labToken }) });
    const labCookie = login.headers.get('set-cookie').split(';')[0];
    const host = await fetch(`${base}/api/host/session`, { method: 'POST', headers: { cookie: labCookie, origin: base, 'content-type': 'application/json' },
      body: JSON.stringify({ token: agentToken }) });
    const cookie = `${labCookie}; ${host.headers.get('set-cookie').split(';')[0]}`;
    const decision = await (await fetch(`${base}/api/host/decision?ip=8.8.8.8`, { headers: { cookie } })).json();
    assert.equal(decision.outcome, 'kernel_block_confirmed');
    assert.equal(decision.global_xdp_drop_totals.ipv4.packets, 9);
    const history = await (await fetch(`${base}/api/host/history?ip=8.8.8.8`, { headers: { cookie } })).json();
    assert.equal(history.events[0].operation, 'apply');
    const postPreview = (origin) => fetch(`${base}/api/host/preview`, { method: 'POST',
      headers: { cookie, origin, 'content-type': 'application/json' }, body: JSON.stringify({ ip: '8.8.8.8', ttl_seconds: 60 }) });
    assert.equal((await postPreview('https://untrusted.example')).status, 403);
    const preview = await postPreview(base);
    assert.equal(preview.status, 200);
    assert.equal((await preview.json()).simulation, 'no packet replay');
    assert.equal(writes, 0);
  } finally { await new Promise((resolve) => server.close(resolve)); }
});

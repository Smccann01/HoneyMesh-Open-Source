import test from 'node:test';
import assert from 'node:assert/strict';
import { createFirewallLab } from '../src/firewall.mjs';
import { createFirewallServer } from '../src/server.mjs';
import { AgentError, createAgentControl } from '../src/agent-control.mjs';
import { createServer as createHttpsServer } from 'node:https';
import { X509Certificate } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';

const config = { url: 'https://127.0.0.1:8443', fingerprint_sha256: Array(32).fill('AA').join(':') };

test('decision API adapter uses exact validated addresses and bounded history', async () => {
  const calls = [];
  const control = createAgentControl(config, async (_config, path, _token, method, body) => {
    calls.push({ path, method, body }); return { ok: true };
  });
  assert.throws(() => control.decision('token', 'not-an-ip'), { message: 'invalid_source_ip' });
  assert.throws(() => control.history('token', '8.8.8.8', 101), { message: 'invalid_history_query' });
  assert.throws(() => control.preview('token', { ip: '8.8.8.8', ttl_seconds: 86401 }), { message: 'invalid_preview_request' });
  await control.decision('token', '2001:db8::3');
  await control.history('token', '8.8.8.8', 25);
  await control.preview('token', { ip: '8.8.8.8', ttl_seconds: 60 });
  assert.deepEqual(calls, [
    { path: '/api/enforcement/decision?ip=2001%3Adb8%3A%3A3', method: undefined, body: undefined },
    { path: '/api/enforcement/history?ip=8.8.8.8&limit=25', method: undefined, body: undefined },
    { path: '/api/enforcement/preview', method: 'POST', body: { ip: '8.8.8.8', ttl_seconds: 60 } },
  ]);
});

test('agent adapter bounds source and TTL and never calls broad release', async () => {
  const calls = [];
  const control = createAgentControl(config, async (_config, path, token, method, body) => {
    calls.push({ path, token, method, body });
    return path === '/api/enforcement/contract' ? { contract_version: 1, operator_grants: true, scoped_release: true,
      uee_ready: true, xdp_attached: true, mode: 'ENFORCE' } : { ok: true };
  });
  assert.equal(createAgentControl({ ...config, url: 'https://example.com' }), null);
  await assert.rejects(control.authenticate('short'), { message: 'agent_unauthorized' });
  await control.authenticate('x'.repeat(64));
  await assert.rejects(control.ban('x'.repeat(64), { ip: 'not-an-ip', ttl_seconds: 60 }), { message: 'invalid_bounded_ban' });
  await assert.rejects(control.ban('x'.repeat(64), { ip: '203.0.113.3', ttl_seconds: 86401 }), { message: 'invalid_bounded_ban' });
  await control.ban('x'.repeat(64), { ip: '2001:db8::3', ttl_seconds: 60 });
  await control.ban('x'.repeat(64), { ip: '2001:db8::3', ttl_seconds: 86400 });
  await assert.rejects(control.release('x'.repeat(64), { ip: '2001:db8::3', grant_id: 'detection' }), { message: 'invalid_operator_grant' });
  await control.release('x'.repeat(64), { ip: '2001:db8::3', grant_id: `firewall-console:${'a'.repeat(32)}` });
  await assert.rejects(control.returnToTest('x'.repeat(64), { confirm: 'yes' }), { message: 'confirmation_required' });
  await control.returnToTest('x'.repeat(64), { confirm: 'RETURN TO TEST' });
  assert.deepEqual(calls.map((call) => call.path), ['/api/bans', '/api/enforcement/contract', '/api/enforcement/operator-grants',
    '/api/enforcement/contract', '/api/enforcement/operator-grants',
    '/api/enforcement/contract', '/api/enforcement/operator-grants/release', '/api/mode']);
  assert.deepEqual(calls[2].body, { ip: '2001:db8::3', ttl_seconds: 60, reason: 'firewall console operator' });
  assert.deepEqual(calls[4].body, { ip: '2001:db8::3', ttl_seconds: 86400, reason: 'firewall console operator' });
  assert.deepEqual(calls[6].body, { ip: '2001:db8::3', grant_id: `firewall-console:${'a'.repeat(32)}` });
});

test('agent contract denial stops new grants but permits exact release and TEST recovery', async () => {
  const paths = [];
  const control = createAgentControl(config, async (_config, path) => {
    paths.push(path);
    return path === '/api/enforcement/contract' ? { contract_version: 1, operator_grants: false,
      scoped_release: true, uee_ready: true, xdp_attached: true, mode: 'ENFORCE' } : { ok: true };
  });
  await assert.rejects(control.ban('x'.repeat(64), { ip: '203.0.113.3', ttl_seconds: 60 }), { message: 'operator_grants_unavailable' });
  await control.release('x'.repeat(64), { ip: '203.0.113.3', grant_id: `firewall-console:${'a'.repeat(32)}` });
  await control.returnToTest('x'.repeat(64), { confirm: 'RETURN TO TEST' });
  assert.deepEqual(paths, ['/api/enforcement/contract', '/api/enforcement/contract',
    '/api/enforcement/operator-grants/release', '/api/mode']);
});

test('TLS pin is verified before the operator token reaches a local HTTPS service', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'hm-agent-pin-'));
  const keyPath = join(dir, 'key.pem');
  const certPath = join(dir, 'cert.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=localhost',
    '-keyout', keyPath, '-out', certPath, '-days', '1'], { stdio: 'ignore' });
  const key = await readFile(keyPath);
  const cert = await readFile(certPath);
  const seen = [];
  const server = createHttpsServer({ key, cert }, (request, response) => {
    seen.push(request.headers['x-honey-token']);
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end('{}');
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const url = `https://127.0.0.1:${server.address().port}`;
  try {
    const wrong = createAgentControl({ url, fingerprint_sha256: Array(32).fill('00').join(':') });
    await assert.rejects(wrong.authenticate('x'.repeat(64)), { message: 'agent_tls_pin_mismatch' });
    assert.deepEqual(seen, []);
    const fingerprint_sha256 = new X509Certificate(cert).fingerprint256;
    const right = createAgentControl({ url, fingerprint_sha256 });
    assert.equal(await right.authenticate('x'.repeat(64)), true);
    assert.deepEqual(seen, ['x'.repeat(64)]);
  } finally {
    await new Promise((resolve) => server.close(resolve));
    await rm(dir, { recursive: true });
  }
});

test('host controls need both sessions; writes are default-closed and same-origin', async () => {
  const labToken = 'l'.repeat(64);
  const operatorToken = 'o'.repeat(64);
  const calls = [];
  const agentControl = {
    authenticate: async (token) => { if (token !== operatorToken) throw new AgentError(401, 'agent_unauthorized'); },
    grants: async () => [{ state: { ip: '203.0.113.3' } }],
    counters: async () => ({ ipv4: 7 }),
    interfaces: async () => [{ name: 'eth0' }],
    ban: async (_token, body) => { calls.push(body); return { ok: true }; },
    returnToTest: async () => ({ mode: 'TEST' }),
  };
  const server = createFirewallServer({ lab: createFirewallLab({ webhookSecret: 's'.repeat(64) }),
    adminToken: labToken, html: '', script: '', agentControl });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  const post = (path, cookie, body, origin = base) => fetch(`${base}${path}`, {
    method: 'POST', headers: { origin, cookie, 'content-type': 'application/json' }, body: JSON.stringify(body),
  });
  try {
    const lab = await post('/api/session', '', { token: labToken });
    assert.equal(lab.status, 200);
    const labCookie = lab.headers.get('set-cookie').split(';')[0];
    assert.equal((await fetch(`${base}/api/host/grants`, { headers: { cookie: labCookie } })).status, 401);
    assert.equal((await post('/api/host/session', labCookie, { token: 'bad' })).status, 401);
    assert.equal((await post('/api/host/session', labCookie, { token: operatorToken }, 'https://other.example')).status, 403);
    const login = await post('/api/host/session', labCookie, { token: operatorToken });
    assert.equal(login.status, 200);
    assert.equal((await login.json()).actions_enabled, false);
    const hostCookie = login.headers.get('set-cookie').split(';')[0];
    const cookie = `${labCookie}; ${hostCookie}`;
    assert.equal((await fetch(`${base}/api/host/grants`, { headers: { cookie } })).status, 200);
    assert.equal((await post('/api/host/ban', cookie, { ip: '203.0.113.3', ttl_seconds: 60 })).status, 503);
    assert.equal((await post('/api/host/release', cookie, { ip: '203.0.113.3' })).status, 503);
    assert.equal(calls.length, 0);
    const logout = await fetch(`${base}/api/session`, { method: 'DELETE', headers: { cookie, origin: base } });
    assert.equal(logout.status, 200);
    assert.equal((await fetch(`${base}/api/host/grants`, { headers: { cookie } })).status, 401);
  } finally { await new Promise((resolve) => server.close(resolve)); }
});

test('test-enabled writes record outcomes without credentials and never expose broad release', async () => {
  const labToken = 'l'.repeat(64);
  const operatorToken = 'o'.repeat(64);
  const agentControl = {
    authenticate: async () => {}, grants: async () => [], counters: async () => ({}), interfaces: async () => [],
    contract: async () => ({ contract_version: 1, operator_grants: true, scoped_release: true, uee_ready: true,
      xdp_attached: true, mode: 'ENFORCE' }),
    ban: async (_token, body) => { if (body.ttl_seconds > 86400) throw new AgentError(400, 'invalid_bounded_ban'); return { ok: true }; },
    release: async (_token, body) => ({ grant_removed: true, grant_id: body.grant_id }),
    returnToTest: async () => ({ mode: 'TEST' }),
  };
  const server = createFirewallServer({ lab: createFirewallLab({ webhookSecret: 's'.repeat(64) }),
    adminToken: labToken, html: '', script: '', agentControl, hostActionsEnabled: true });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  const post = (path, cookie, body, origin = base) => fetch(`${base}${path}`, {
    method: 'POST', headers: { origin, cookie, 'content-type': 'application/json' }, body: JSON.stringify(body),
  });
  try {
    const lab = await post('/api/session', '', { token: labToken });
    const labCookie = lab.headers.get('set-cookie').split(';')[0];
    const login = await post('/api/host/session', labCookie, { token: operatorToken });
    const cookie = `${labCookie}; ${login.headers.get('set-cookie').split(';')[0]}`;
    assert.equal((await post('/api/host/ban', cookie, { ip: '203.0.113.3', ttl_seconds: 60 }, 'https://other.example')).status, 403);
    assert.equal((await post('/api/host/ban', cookie, { ip: '203.0.113.3', ttl_seconds: 86401 })).status, 400);
    assert.equal((await post('/api/host/ban', cookie, { ip: '203.0.113.3', ttl_seconds: 60 })).status, 200);
    assert.equal((await post('/api/host/ban', cookie, { ip: '203.0.113.3', ttl_seconds: 86400 })).status, 200);
    assert.equal((await post('/api/host/test-mode', cookie, { confirm: 'RETURN TO TEST' })).status, 200);
    assert.equal((await post('/api/host/release', cookie, { ip: '203.0.113.3', grant_id: `firewall-console:${'a'.repeat(32)}` })).status, 200);
    const audit = await (await fetch(`${base}/api/host/audit`, { headers: { cookie } })).json();
    assert.deepEqual(audit.map((event) => event.result), ['invalid_bounded_ban', 'accepted', 'accepted', 'accepted', 'accepted']);
    assert.equal(JSON.stringify(audit).includes(operatorToken), false);
  } finally { await new Promise((resolve) => server.close(resolve)); }
});

test('console refuses a new block when the agent denies grant creation while allowing scoped release', async () => {
  const labToken = 'l'.repeat(64);
  let created = false;
  const agentControl = {
    authenticate: async () => {},
    contract: async () => ({ contract_version: 1, operator_grants: false, scoped_release: true,
      uee_ready: true, xdp_attached: true, mode: 'ENFORCE' }),
    ban: async () => { created = true; return {}; },
    release: async () => ({ grant_removed: true }),
  };
  const server = createFirewallServer({ lab: createFirewallLab({ webhookSecret: 's'.repeat(64) }),
    adminToken: labToken, html: '', script: '', agentControl, hostActionsEnabled: true });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  const post = (path, cookie, body) => fetch(`${base}${path}`, { method: 'POST',
    headers: { origin: base, cookie, 'content-type': 'application/json' }, body: JSON.stringify(body) });
  try {
    const session = await post('/api/session', '', { token: labToken });
    const labCookie = session.headers.get('set-cookie').split(';')[0];
    const host = await post('/api/host/session', labCookie, { token: 'o'.repeat(64) });
    const cookie = `${labCookie}; ${host.headers.get('set-cookie').split(';')[0]}`;
    const status = await (await fetch(`${base}/api/host/session`, { headers: { cookie } })).json();
    assert.equal(status.grant_creation_entitled, false);
    assert.equal(status.ban_enabled, false);
    assert.equal(status.scoped_actions_enabled, true);
    assert.equal((await post('/api/host/ban', cookie, { ip: '203.0.113.3', ttl_seconds: 60 })).status, 409);
    assert.equal(created, false);
    assert.equal((await post('/api/host/release', cookie, { ip: '203.0.113.3', grant_id: `firewall-console:${'a'.repeat(32)}` })).status, 200);
  } finally { await new Promise((resolve) => server.close(resolve)); }
});

test('older agent contract keeps scoped writes closed even with test flag enabled', async () => {
  const labToken = 'l'.repeat(64);
  const operatorToken = 'o'.repeat(64);
  let banCalled = false;
  const agentControl = {
    authenticate: async () => {}, grants: async () => [], counters: async () => ({}), interfaces: async () => [],
    contract: async () => { throw new AgentError(404, 'agent_contract_unavailable'); },
    ban: async () => { banCalled = true; return {}; }, returnToTest: async () => ({ mode: 'TEST' }),
  };
  const server = createFirewallServer({ lab: createFirewallLab({ webhookSecret: 's'.repeat(64) }),
    adminToken: labToken, html: '', script: '', agentControl, hostActionsEnabled: true });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  const post = (path, cookie, body) => fetch(`${base}${path}`, { method: 'POST',
    headers: { origin: base, cookie, 'content-type': 'application/json' }, body: JSON.stringify(body) });
  try {
    const lab = await post('/api/session', '', { token: labToken });
    const labCookie = lab.headers.get('set-cookie').split(';')[0];
    const login = await post('/api/host/session', labCookie, { token: operatorToken });
    const cookie = `${labCookie}; ${login.headers.get('set-cookie').split(';')[0]}`;
    const state = await (await fetch(`${base}/api/host/session`, { headers: { cookie } })).json();
    assert.equal(state.contract_status, 'upgrade_required');
    assert.equal(state.scoped_actions_enabled, false);
    assert.equal((await post('/api/host/ban', cookie, { ip: '203.0.113.3', ttl_seconds: 60 })).status, 409);
    assert.equal(banCalled, false);
  } finally { await new Promise((resolve) => server.close(resolve)); }
});

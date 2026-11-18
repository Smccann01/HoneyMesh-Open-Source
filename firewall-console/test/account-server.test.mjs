import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createFirewallLab } from '../src/firewall.mjs';
import { createFirewallServer } from '../src/server.mjs';
import { createOperatorAccount } from '../src/operator-account.mjs';
import { AgentError } from '../src/agent-control.mjs';

test('local admin account gates saved host token and survives a server restart', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'hm-account-api-'));
  const path = join(dir, 'operator-account.json');
  const bootstrap = 'b'.repeat(64);
  const agentToken = 'a'.repeat(64);
  const password = 'a long local admin password 123!';
  const seen = [];
  const agentControl = {
    authenticate: async (token) => { if (token !== agentToken) throw new AgentError(401, 'agent_unauthorized'); },
    grants: async (token) => { seen.push(token); return [{ state: { IP: '203.0.113.3' } }]; },
    counters: async () => ({}), interfaces: async () => [],
    ban: async () => ({ ok: true }), returnToTest: async () => ({ mode: 'TEST' }),
  };
  const makeServer = async () => createFirewallServer({ lab: createFirewallLab({ webhookSecret: 'w'.repeat(64) }),
    adminToken: bootstrap, html: '', script: '', agentControl,
    operatorAccount: await createOperatorAccount(path) });
  let server = await makeServer();
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  let base = `http://127.0.0.1:${server.address().port}`;
  const post = (route, body, cookie = '', origin = base) => fetch(`${base}${route}`, { method: 'POST',
    headers: { cookie, origin, 'content-type': 'application/json' }, body: JSON.stringify(body) });
  try {
    assert.equal((await fetch(`${base}/api/account/state`)).status, 200);
    assert.equal((await post('/api/account/setup', { bootstrap_token: 'wrong', username: 'admin', password })).status, 400);
    assert.equal((await post('/api/account/setup', { bootstrap_token: bootstrap, username: 'admin', password }, '', 'https://other.example')).status, 403);
    const setup = await post('/api/account/setup', { bootstrap_token: bootstrap, username: 'admin', password });
    assert.equal(setup.status, 200);
    const cookie = setup.headers.get('set-cookie').split(';')[0];
    assert.equal((await post('/api/account/setup', { bootstrap_token: bootstrap, username: 'admin', password })).status, 409);
    assert.equal((await post('/api/session', { token: bootstrap })).status, 409);
    assert.equal((await fetch(`${base}/api/status`, { headers: { authorization: `Bearer ${bootstrap}` } })).status, 401);
    assert.equal((await fetch(`${base}/api/status`, { headers: { cookie } })).status, 200);
    assert.equal((await fetch(`${base}/api/host/grants`, { headers: { cookie } })).status, 401);
    assert.equal((await post('/api/account/agent-token', { token: agentToken }, cookie, 'https://other.example')).status, 403);
    assert.equal((await post('/api/account/agent-token', { token: 'x'.repeat(64) }, cookie)).status, 401);
    assert.equal((await post('/api/account/agent-token', { token: agentToken }, cookie)).status, 200);
    assert.equal((await readFile(path, 'utf8')).includes(agentToken), false);
    assert.equal((await fetch(`${base}/api/host/grants`, { headers: { cookie } })).status, 200);
    assert.deepEqual(seen, [agentToken]);
    assert.equal((await post('/api/host/ban', { ip: '203.0.113.3', ttl_seconds: 60 }, cookie)).status, 503);
    await new Promise((resolve) => server.close(resolve));
    server = await makeServer();
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    base = `http://127.0.0.1:${server.address().port}`;
    assert.equal((await fetch(`${base}/api/account/session`, { headers: { cookie } })).status, 200);
    assert.equal((await fetch(`${base}/api/host/grants`, { headers: { cookie } })).status, 200);
    const logout = await fetch(`${base}/api/session`, { method: 'DELETE', headers: { cookie, origin: base } });
    assert.equal(logout.status, 200);
    assert.equal((await fetch(`${base}/api/host/grants`, { headers: { cookie } })).status, 401);
    assert.equal((await post('/api/account/session', { username: 'admin', password: 'wrong password' })).status, 401);
    const login = await post('/api/account/session', { username: 'admin', password });
    assert.equal(login.status, 200);
    const restored = login.headers.get('set-cookie').split(';')[0];
    assert.equal((await fetch(`${base}/api/host/grants`, { headers: { cookie: restored } })).status, 200);
    assert.equal((await post('/api/account/password', { current_password: password, new_password: 'another long admin password 456!' }, restored, 'https://other.example')).status, 403);
    const changed = await post('/api/account/password', { current_password: password, new_password: 'another long admin password 456!' }, restored);
    assert.equal(changed.status, 200);
    const changedCookie = changed.headers.get('set-cookie').split(';')[0];
    assert.equal((await fetch(`${base}/api/host/grants`, { headers: { cookie: restored } })).status, 401);
    assert.equal((await fetch(`${base}/api/host/grants`, { headers: { cookie: changedCookie } })).status, 200);
    for (let attempt = 0; attempt < 5; attempt++) {
      assert.equal((await post('/api/account/session', { username: 'admin', password: 'wrong password' })).status, 401);
    }
    assert.equal((await post('/api/account/session', { username: 'admin', password: 'another long admin password 456!' })).status, 429);
  } finally {
    if (server.listening) await new Promise((resolve) => server.close(resolve));
    await rm(dir, { recursive: true });
  }
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { createFirewallLab } from '../src/firewall.mjs';
import { createFirewallServer } from '../src/server.mjs';

test('signed browser session restores access, rejects cross-origin writes, and signs out', async () => {
  const adminToken = 'a'.repeat(64);
  const server = createFirewallServer({ lab: createFirewallLab({ webhookSecret: 'b'.repeat(64) }),
    adminToken, adminTokenExpiresAt: new Date(Date.now() + 60_000).toISOString(), html: '', script: '' });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    assert.equal((await fetch(`${base}/api/status`)).status, 401);
    assert.equal((await fetch(`${base}/api/session`, { method: 'POST',
      headers: { origin: 'https://other.example', 'content-type': 'application/json' },
      body: JSON.stringify({ token: adminToken }) })).status, 403);
    const login = await fetch(`${base}/api/session`, { method: 'POST',
      headers: { origin: base, 'content-type': 'application/json' },
      body: JSON.stringify({ token: adminToken }) });
    assert.equal(login.status, 200);
    const cookieHeader = login.headers.get('set-cookie');
    assert.match(cookieHeader, /HttpOnly; SameSite=Strict; Path=\/api/);
    assert.ok(!cookieHeader.includes(adminToken));
    const cookie = cookieHeader.split(';')[0];
    const session = await fetch(`${base}/api/session`, { headers: { cookie } });
    assert.equal(session.status, 200);
    assert.ok(Date.parse((await session.json()).expires_at) <= Date.now() + 60_000);
    assert.equal((await fetch(`${base}/api/status`, { headers: { cookie } })).status, 200);
    assert.equal((await fetch(`${base}/api/lab/attempt`, { method: 'POST',
      headers: { cookie, 'content-type': 'application/json', origin: 'https://other.example' },
      body: JSON.stringify({ source_ip: '8.8.8.8' }) })).status, 403);
    const logout = await fetch(`${base}/api/session`, { method: 'DELETE', headers: { cookie, origin: base } });
    assert.equal(logout.status, 200);
    assert.match(logout.headers.get('set-cookie'), /Max-Age=0/);
  } finally { await new Promise((resolve) => server.close(resolve)); }
});

test('expired credential cannot create or restore a browser session', async () => {
  const adminToken = 'a'.repeat(64);
  const server = createFirewallServer({ lab: createFirewallLab({ webhookSecret: 'b'.repeat(64) }),
    adminToken, adminTokenExpiresAt: new Date(Date.now() - 1_000).toISOString(), html: '', script: '' });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    const base = `http://127.0.0.1:${server.address().port}`;
    const result = await fetch(`${base}/api/session`, { method: 'POST', headers: { origin: base, 'content-type': 'application/json' }, body: JSON.stringify({ token: adminToken }) });
    assert.equal(result.status, 401);
  } finally { await new Promise((resolve) => server.close(resolve)); }
});

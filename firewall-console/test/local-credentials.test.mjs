import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createFirewallLab } from '../src/firewall.mjs';
import { loadLocalCredentials } from '../src/local-credentials.mjs';
import { createFirewallServer } from '../src/server.mjs';

test('local admin token lasts 30 days, rotates on restart, and is separate from webhook secret', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'ng-credentials-'));
  const path = join(directory, 'private', 'credentials.json');
  const day = 24 * 60 * 60 * 1_000;
  try {
    const first = await loadLocalCredentials(path, () => 1_000_000);
    assert.equal(Date.parse(first.adminTokenExpiresAt), 1_000_000 + 30 * day);
    assert.equal((await stat(path)).mode & 0o077, 0);
    const same = await loadLocalCredentials(path, () => 1_000_000 + 29 * day);
    assert.equal(same.adminToken, first.adminToken);
    const rotated = await loadLocalCredentials(path, () => 1_000_000 + 30 * day);
    assert.notEqual(rotated.adminToken, first.adminToken);
    assert.equal(rotated.webhookSecret, first.webhookSecret);
    assert.equal(JSON.parse(await readFile(path, 'utf8')).adminToken, rotated.adminToken);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('legacy local credential gets a bounded expiry without changing its token', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'ng-legacy-'));
  const path = join(directory, 'credentials.json');
  try {
    await writeFile(path, JSON.stringify({ adminToken: 'a'.repeat(64), webhookSecret: 'b'.repeat(64) }),
      { mode: 0o600 });
    const updated = await loadLocalCredentials(path, () => 1_000_000);
    assert.equal(updated.adminToken, 'a'.repeat(64));
    assert.ok(Number.isFinite(Date.parse(updated.adminTokenExpiresAt)));
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('HTTP admin access expires independently of the customer license system', async () => {
  const server = createFirewallServer({
    lab: createFirewallLab({ webhookSecret: 'b'.repeat(64) }),
    adminToken: 'a'.repeat(64), adminTokenExpiresAt: '2000-01-01T00:00:00.000Z',
    html: '<h1>test</h1>', script: '',
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    const response = await fetch(`http://127.0.0.1:${server.address().port}/api/status`, {
      headers: { authorization: `Bearer ${'a'.repeat(64)}` },
    });
    assert.equal(response.status, 401);
  } finally { await new Promise((resolve) => server.close(resolve)); }
});

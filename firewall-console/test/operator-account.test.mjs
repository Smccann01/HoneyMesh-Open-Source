import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createOperatorAccount } from '../src/operator-account.mjs';

test('account preserves encrypted agent access across restart and revokes cookies on sign-out', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'hm-operator-test-'));
  const path = join(dir, 'operator-account.json');
  let current = 1_000_000;
  try {
    const first = await createOperatorAccount(path, () => current);
    assert.equal(first.configured(), false);
    await assert.rejects(first.setup(false, 'admin', 'correct horse battery staple!'), { message: 'invalid_account_setup' });
    await assert.rejects(first.setup(true, 'admin', 'short'), { message: 'invalid_account_setup' });
    const created = await first.setup(true, 'admin', 'correct horse battery staple!');
    const cookie = created.cookie.split(';')[0];
    assert.match(created.cookie, /HttpOnly; SameSite=Strict; Path=\/api/);
    assert.equal(first.session(cookie).username, 'admin');
    assert.equal((await stat(path)).mode & 0o777, 0o600);
    await assert.rejects(first.login('admin', 'wrong password'), { message: 'invalid_credentials' });
    await first.saveAgentToken(first.session(cookie), 'z'.repeat(64), { authenticate: async (token) => {
      assert.equal(token, 'z'.repeat(64));
    } });
    assert.equal((await readFile(path, 'utf8')).includes('z'.repeat(64)), false);
    const restarted = await createOperatorAccount(path, () => current);
    assert.equal(restarted.agentToken(restarted.session(cookie)), 'z'.repeat(64));
    current += 24 * 24 * 60 * 60 * 1_000;
    const renewed = restarted.renew(restarted.session(cookie));
    assert.ok(renewed?.expiresAt > created.expiresAt);
    await restarted.logout();
    assert.equal(restarted.session(cookie), null);
    assert.equal(restarted.session(renewed.cookie.split(';')[0]), null);
    const login = await restarted.login('admin', 'correct horse battery staple!');
    assert.equal(restarted.agentToken(restarted.session(login.cookie.split(';')[0])), 'z'.repeat(64));
    const oldSession = restarted.session(login.cookie.split(';')[0]);
    await assert.rejects(restarted.changePassword(oldSession, 'incorrect', 'a much stronger replacement password!'), { message: 'invalid_credentials' });
    const changed = await restarted.changePassword(oldSession, 'correct horse battery staple!', 'a much stronger replacement password!');
    assert.equal(restarted.session(login.cookie.split(';')[0]), null);
    await assert.rejects(restarted.login('admin', 'correct horse battery staple!'), { message: 'invalid_credentials' });
    assert.equal(restarted.agentToken(restarted.session(changed.cookie.split(';')[0])), 'z'.repeat(64));
    await assert.rejects(restarted.saveAgentToken(oldSession, 'z'.repeat(64), { authenticate: async () => {} }),
      { message: 'operator_session_required' });
  } finally { await rm(dir, { recursive: true }); }
});

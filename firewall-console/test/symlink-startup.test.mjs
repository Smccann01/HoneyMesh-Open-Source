import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, rm, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';

test('console starts when invoked through a release symlink', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'firewall-symlink-'));
  const entry = join(directory, 'server.mjs');
  await symlink(fileURLToPath(new URL('../src/server.mjs', import.meta.url)), entry);
  const port = 20_000 + Math.floor(Math.random() * 30_000);
  const child = spawn(process.execPath, [entry], {
    env: { ...process.env, HM_CONSOLE_STATE_DIR: join(directory, 'state'), LAB_PORT: String(port) },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const closed = new Promise((resolve) => child.once('close', resolve));
  let output = '';
  child.stdout.on('data', (chunk) => { output += chunk; });
  child.stderr.on('data', (chunk) => { output += chunk; });
  try {
    for (let attempt = 0; attempt < 50 && !output.includes('Network Decode Firewall Console:'); attempt++) {
      if (child.exitCode !== null) break;
      await delay(100);
    }
    assert.match(output, /Network Decode Firewall Console: http:\/\/127\.0\.0\.1:/);
    assert.equal(child.exitCode, null);
  } finally {
    child.kill('SIGTERM');
    await closed;
    await rm(directory, { recursive: true, force: true });
  }
});

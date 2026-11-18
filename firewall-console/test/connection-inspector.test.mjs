import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { findSocketProcess, inspectConnection, serviceHint } from '../src/connection-inspector.mjs';

test('connection inspector attributes only a matching readable socket inode', async () => {
  const root = await mkdtemp(join(tmpdir(), 'hm-proc-fixture-'));
  try {
    await mkdir(join(root, '123', 'fd'), { recursive: true });
    await writeFile(join(root, '123', 'comm'), 'billing-api\n');
    await symlink('socket:[98765]', join(root, '123', 'fd', '7'));
    assert.deepEqual(await findSocketProcess('98765', { procRoot: root }),
      { process_name: 'billing-api', pid: 123, reason: 'proc_socket_inode_match' });
    const result = await inspectConnection({ inode: '98765', remote_address: '203.0.113.4', remote_port: 443 }, { procRoot: root });
    assert.equal(result.process_name, 'billing-api');
    assert.equal(result.service_hint, 'HTTPS');
    assert.equal(result.reverse_dns, null);
    assert.equal(result.reverse_dns_is_site_identity, false);
    assert.equal((await findSocketProcess('1', { procRoot: root })).process_name, null);
    assert.equal(serviceHint(49152), null);
    await assert.rejects(inspectConnection({ inode: '../bad', remote_address: '203.0.113.4', remote_port: 443 }), RangeError);
  } finally { await rm(root, { recursive: true, force: true }); }
});

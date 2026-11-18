import test from 'node:test';
import assert from 'node:assert/strict';
import { decodeAddress, parseSocketTable, parseInterfaces, collectKernelTelemetry, selectConnections } from '../src/kernel-telemetry.mjs';
import { createFirewallServer } from '../src/server.mjs';
import { createKernelHistory } from '../src/kernel-history.mjs';

test('kernel socket and interface tables decode address families and counters', () => {
  assert.deepEqual(decodeAddress('0100007F:1F90', 4), { address: '127.0.0.1', port: 8080 });
  assert.deepEqual(decodeAddress('00000000000000000000000001000000:01BB', 6), { address: '::1', port: 443 });
  assert.deepEqual(decodeAddress('0000000000000000FFFF0000EF00000A:2382', 6), { address: '::ffff:10.0.0.239', port: 9090 });
  const rows = parseSocketTable('header\n 0: 0100007F:1F90 00000000:0000 0A 0:0 0:0 0 0 0\n', 'tcp', 4);
  assert.equal(rows[0].state, 'LISTEN');
  assert.equal(rows[0].local, '127.0.0.1:8080');
  assert.equal(rows[0].local_address, '127.0.0.1');
  assert.equal(rows[0].remote_address, '0.0.0.0');
  assert.equal(rows[0].remote_port, 0);
  const detailed = parseSocketTable('header\n 0: 0100007F:1F90 0200007F:01BB 01 00000010:00000002 00:00000000 00000000 1000 0 12345\n', 'tcp', 4)[0];
  assert.equal(detailed.tx_queue_bytes, 16);
  assert.equal(detailed.rx_queue_bytes, 2);
  assert.equal(detailed.uid, 1000);
  assert.equal(detailed.inode, '12345');
  assert.deepEqual(parseInterfaces('header\nheader\n eth0: 100 2 0 1 0 0 0 0 200 3 0 4 0 0 0 0\n')[0],
    { name: 'eth0', rx_bytes: '100', rx_packets: '2', rx_drops: '1', tx_bytes: '200', tx_packets: '3', tx_drops: '4' });
});

test('kernel telemetry requires local admin authentication', async () => {
  const server = createFirewallServer({ lab: { status: () => ({}) }, adminToken: 'x'.repeat(32), html: '', script: '', kernelTelemetry: async () => ({ summary: { sockets: 1 } }) });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    const url = `http://127.0.0.1:${server.address().port}/api/kernel/telemetry`;
    assert.equal((await fetch(url)).status, 401);
    const response = await fetch(url, { headers: { authorization: `Bearer ${'x'.repeat(32)}` } });
    assert.equal(response.status, 200);
    assert.equal((await response.json()).summary.sockets, 1);
    assert.equal((await fetch(`${url.replace('/telemetry', '/history')}`)).status, 401);
    const history = await fetch(`${url.replace('/telemetry', '/history')}`, { headers: { authorization: `Bearer ${'x'.repeat(32)}` } });
    assert.equal(history.status, 200);
    assert.equal((await history.json()).scope, 'current_process_network_namespace');
  } finally { server.close(); }
});

test('connection process details stay behind the local admin session', async () => {
  const server = createFirewallServer({ lab: { status: () => ({}) }, adminToken: 'x'.repeat(32), html: '', script: '',
    connectionInspector: async () => ({ process_name: 'test-service', pid: 12, reverse_dns_is_site_identity: false }) });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    const url = `http://127.0.0.1:${server.address().port}/api/kernel/connection?inode=12&remote_address=203.0.113.5&remote_port=443`;
    assert.equal((await fetch(url)).status, 401);
    const response = await fetch(url, { headers: { authorization: `Bearer ${'x'.repeat(32)}` } });
    assert.equal(response.status, 200);
    assert.equal((await response.json()).process_name, 'test-service');
  } finally { server.close(); }
});

test('kernel history retains bounded aggregate samples and reports collector errors', async () => {
  let count = 0;
  const history = createKernelHistory(async () => {
    count++;
    if (count === 4) throw new Error('sensitive collector detail');
    return { captured_at: new Date(1_000 * count).toISOString(), summary: { sockets: count, established: count - 1, listening: 1,
      protocols: { tcp4: count }, states: { ESTABLISHED: count - 1 } },
      interfaces: [{ name: 'eth0', rx_bytes: String(count * 100), tx_bytes: String(count * 50) }], connections: [{ remote: 'private' }] };
  }, { maxSamples: 2, intervalMs: 100 });
  await history.sample(); await history.sample(); await history.sample();
  const snapshot = history.snapshot();
  assert.equal(snapshot.retained_samples, 2);
  assert.deepEqual(snapshot.samples.map((sample) => sample.summary.sockets), [2, 3]);
  assert.equal(JSON.stringify(snapshot).includes('private'), false);
  await history.sample();
  assert.equal(history.snapshot().last_error, 'sample_unavailable');
  assert.equal(history.snapshot().retained_samples, 2);
});

test('live Linux kernel telemetry has bounded socket results', async () => {
  const result = await collectKernelTelemetry();
  assert.equal(result.scope, 'current_process_network_namespace');
  assert.ok(result.connections.length <= 200);
  assert.ok(result.interfaces.length > 0);
});

test('kernel connection selection filters and pages the full snapshot', () => {
  const rows = Array.from({ length: 260 }, (_, index) => ({ protocol: index % 2 ? 'tcp4' : 'tcp6', local: `127.0.0.1:${index}`, remote: '10.0.0.1:443', state: index % 2 ? 'ESTABLISHED' : 'LISTEN' }));
  const first = selectConnections(rows, { protocol: 'tcp4', state: 'ESTABLISHED', sort: 'local', offset: 0, limit: 100 });
  assert.equal(first.matched, 130);
  assert.equal(first.connections.length, 100);
  const second = selectConnections(rows, { protocol: 'tcp4', state: 'ESTABLISHED', offset: 100, limit: 100 });
  assert.equal(second.connections.length, 30);
  assert.throws(() => selectConnections(rows, { limit: 1000 }), /invalid_connection_filter/);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { createAgentOverview } from '../src/agent-overview.mjs';
import { createServer as createHttpsServer } from 'node:https';
import { X509Certificate } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';

const config = { url: 'https://127.0.0.1:8443', fingerprint_sha256: Array(32).fill('AA').join(':'),
  ca_certificate: '-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n' };

test('agent overview refuses remote URLs and unpinned configuration', async () => {
  assert.deepEqual(await createAgentOverview({ ...config, url: 'https://example.com' })(), { connected: false, reason: 'not_configured' });
  assert.deepEqual(await createAgentOverview({ ...config, fingerprint_sha256: 'invalid' })(), { connected: false, reason: 'not_configured' });
  assert.deepEqual(await createAgentOverview({ ...config, ca_certificate: undefined })(), { connected: false, reason: 'not_configured' });
});

test('agent overview accepts only matching live mode and health', async () => {
  const good = createAgentOverview(config, async (_url, _fingerprint, _ca, path) => path === '/api/mode'
    ? { mode: 'TEST' } : { mode: 'TEST', status: 'ok', uptime_s: 12, pending_bans: 2, blocks_local: 0, blocks_mesh: 0 });
  const result = await good();
  assert.equal(result.connected, true);
  assert.equal(result.mode, 'TEST');
  assert.equal(result.pending_bans, 2);
  assert.equal(result.controls_available, true);
  assert.equal(result.console_url, 'https://127.0.0.1:8443');
  const mismatch = createAgentOverview(config, async (_url, _fingerprint, _ca, path) => path === '/api/mode' ? { mode: 'TEST' } : { mode: 'ENFORCE' });
  assert.deepEqual(await mismatch(), { connected: false, reason: 'agent_unavailable' });
});

test('agent overview sends no HTTP request until the local TLS pin matches', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'hm-overview-pin-'));
  const keyPath = join(dir, 'key.pem');
  const certPath = join(dir, 'cert.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=localhost',
    '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
    '-keyout', keyPath, '-out', certPath, '-days', '1'], { stdio: 'ignore' });
  const key = await readFile(keyPath);
  const cert = await readFile(certPath);
  const seen = [];
  const server = createHttpsServer({ key, cert }, (request, response) => {
    seen.push(request.url);
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(JSON.stringify(request.url === '/api/mode' ? { mode: 'TEST' } : { mode: 'TEST', status: 'ok' }));
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const url = `https://127.0.0.1:${server.address().port}`;
  try {
    const wrong = createAgentOverview({ url, fingerprint_sha256: Array(32).fill('00').join(':'), ca_certificate: cert.toString('utf8') });
    assert.deepEqual(await wrong(), { connected: false, reason: 'tls_pin_mismatch' });
    assert.deepEqual(seen, []);
    const fingerprint_sha256 = new X509Certificate(cert).fingerprint256.toLowerCase();
    const right = createAgentOverview({ url, fingerprint_sha256, ca_certificate: cert.toString('utf8') });
    assert.equal((await right()).connected, true);
    assert.deepEqual(seen.sort(), ['/api/health', '/api/mode']);
  } finally {
    await new Promise((resolve) => server.close(resolve));
    await rm(dir, { recursive: true });
  }
});

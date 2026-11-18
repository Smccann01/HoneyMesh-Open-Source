import test from 'node:test';
import assert from 'node:assert/strict';
import { createAgentOverview } from '../src/agent-overview.mjs';

const config = { url: 'https://127.0.0.1:8443', fingerprint_sha256: Array(32).fill('AA').join(':') };

test('agent overview refuses remote URLs and unpinned configuration', async () => {
  assert.deepEqual(await createAgentOverview({ ...config, url: 'https://example.com' })(), { connected: false, reason: 'not_configured' });
  assert.deepEqual(await createAgentOverview({ ...config, fingerprint_sha256: 'invalid' })(), { connected: false, reason: 'not_configured' });
});

test('agent overview accepts only matching live mode and health', async () => {
  const good = createAgentOverview(config, async (_url, _fingerprint, path) => path === '/api/mode'
    ? { mode: 'TEST' } : { mode: 'TEST', status: 'ok', uptime_s: 12, pending_bans: 2, blocks_local: 0, blocks_mesh: 0 });
  const result = await good();
  assert.equal(result.connected, true);
  assert.equal(result.mode, 'TEST');
  assert.equal(result.pending_bans, 2);
  assert.equal(result.controls_available, true);
  assert.equal(result.console_url, 'https://127.0.0.1:8443');
  const mismatch = createAgentOverview(config, async (_url, _fingerprint, path) => path === '/api/mode' ? { mode: 'TEST' } : { mode: 'ENFORCE' });
  assert.deepEqual(await mismatch(), { connected: false, reason: 'agent_unavailable' });
});

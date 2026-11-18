import https from 'node:https';
import { timingSafeEqual } from 'node:crypto';

const MAX_RESPONSE = 64 * 1024;

function safeFingerprint(value) {
  return typeof value === 'string' && /^[A-F0-9]{2}(?::[A-F0-9]{2}){31}$/i.test(value);
}

function safeUrl(value) {
  try {
    const url = new URL(value);
    if (url.protocol !== 'https:' || url.hostname !== '127.0.0.1' || url.username || url.password || url.pathname !== '/' || url.search || url.hash) return null;
    return url;
  } catch { return null; }
}

function readPinnedJson(url, fingerprint, path) {
  return new Promise((resolve, reject) => {
    const request = https.request(new URL(path, url), { method: 'GET', rejectUnauthorized: false, timeout: 3_000, agent: false }, (response) => {
      if (response.statusCode !== 200 || !response.headers['content-type']?.startsWith('application/json')) {
        response.resume(); reject(new Error('agent_response_unavailable')); return;
      }
      const chunks = []; let size = 0;
      response.on('data', (chunk) => {
        size += chunk.length;
        if (size > MAX_RESPONSE) { request.destroy(new Error('agent_response_too_large')); return; }
        chunks.push(chunk);
      });
      response.on('end', () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); } catch { reject(new Error('agent_response_invalid')); } });
    });
    request.on('socket', (socket) => socket.on('secureConnect', () => {
      const actual = socket.getPeerCertificate().fingerprint256;
      if (!actual || !timingSafeEqual(Buffer.from(actual), Buffer.from(fingerprint))) request.destroy(new Error('agent_tls_pin_mismatch'));
    }));
    request.on('timeout', () => request.destroy(new Error('agent_timeout')));
    request.on('error', reject);
    request.end();
  });
}

export function createAgentOverview(config, readJson = readPinnedJson) {
  const url = safeUrl(config?.url);
  if (!url || !safeFingerprint(config?.fingerprint_sha256)) return async () => ({ connected: false, reason: 'not_configured' });
  return async () => {
    try {
      const [mode, health] = await Promise.all([
        readJson(url, config.fingerprint_sha256, '/api/mode'),
        readJson(url, config.fingerprint_sha256, '/api/health'),
      ]);
      if (!['TEST', 'ENFORCE', 'LOCKDOWN'].includes(mode?.mode) || mode.mode !== health?.mode) throw new Error('agent_state_mismatch');
      return { connected: true, mode: mode.mode, status: String(health.status ?? 'unknown'),
        uptime_seconds: Number(health.uptime_s ?? 0), pending_bans: Number(health.pending_bans ?? 0),
        local_blocks: Number(health.blocks_local ?? 0), mesh_blocks: Number(health.blocks_mesh ?? 0),
        source: 'pinned_local_honeymesh_dashboard', captured_at: new Date().toISOString(),
        controls_available: true, console_url: url.origin };
    } catch (error) { return { connected: false, reason: error.message === 'agent_tls_pin_mismatch' ? 'tls_pin_mismatch' : 'agent_unavailable' }; }
  };
}

import https from 'node:https';
import tls from 'node:tls';
import { timingSafeEqual } from 'node:crypto';

const MAX_RESPONSE = 64 * 1024;

function safeFingerprint(value) {
  return typeof value === 'string' && /^[A-F0-9]{2}(?::[A-F0-9]{2}){31}$/i.test(value);
}

function safeCa(value) {
  return typeof value === 'string' && value.length <= 16_384 &&
    /^-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----\s*$/.test(value);
}

function safeUrl(value) {
  try {
    const url = new URL(value);
    if (url.protocol !== 'https:' || url.hostname !== '127.0.0.1' || url.username || url.password || url.pathname !== '/' || url.search || url.hash) return null;
    return url;
  } catch { return null; }
}

function readPinnedJson(url, fingerprint, ca, path) {
  // Complete the TLS handshake and check the local agent's certificate before
  // giving the socket to HTTP. The agent uses a self-signed local certificate.
  const agent = new https.Agent({ keepAlive: false });
  agent.createConnection = (_options, callback) => {
    let socket;
    try { socket = tls.connect({ host: '127.0.0.1', port: Number(url.port || 443), servername: 'localhost', ca }); }
    catch { callback(new Error('agent_unavailable')); return; }
    let settled = false;
    const done = (error, connection) => { if (settled) return; settled = true; callback(error, connection); };
    socket.once('secureConnect', () => {
      const actual = socket.getPeerCertificate().fingerprint256;
      if (!socket.authorized || !actual || actual.length !== fingerprint.length || !timingSafeEqual(Buffer.from(actual), Buffer.from(fingerprint))) {
        socket.destroy(); done(new Error('agent_tls_pin_mismatch')); return;
      }
      done(null, socket);
    });
    socket.once('error', () => done(new Error('agent_unavailable')));
  };
  return new Promise((resolve, reject) => {
    const request = https.request(new URL(path, url), { method: 'GET', timeout: 3_000, agent }, (response) => {
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
    request.on('timeout', () => request.destroy(new Error('agent_timeout')));
    request.on('error', reject);
    request.end();
  });
}

export function createAgentOverview(config, readJson = readPinnedJson) {
  const url = safeUrl(config?.url);
  if (!url || !safeFingerprint(config?.fingerprint_sha256) || !safeCa(config?.ca_certificate)) return async () => ({ connected: false, reason: 'not_configured' });
  return async () => {
    try {
      const [mode, health] = await Promise.all([
        readJson(url, config.fingerprint_sha256.toUpperCase(), config.ca_certificate, '/api/mode'),
        readJson(url, config.fingerprint_sha256.toUpperCase(), config.ca_certificate, '/api/health'),
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

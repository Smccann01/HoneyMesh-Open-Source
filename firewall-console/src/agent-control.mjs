import https from 'node:https';
import tls from 'node:tls';
import { timingSafeEqual } from 'node:crypto';
import { isIP } from 'node:net';

const RESPONSE_LIMIT = 256 * 1024;
const FINGERPRINT = /^(?:[A-F0-9]{2}:){31}[A-F0-9]{2}$/i;

function agentConfig(config) {
  try {
    const url = new URL(config?.url);
    if (url.protocol !== 'https:' || url.hostname !== '127.0.0.1' || url.username || url.password || url.pathname !== '/' || url.search || url.hash || !FINGERPRINT.test(config?.fingerprint_sha256 ?? '')) return null;
    return { url, fingerprint: config.fingerprint_sha256.toUpperCase() };
  } catch { return null; }
}

export class AgentError extends Error {
  constructor(status, code) { super(code); this.status = status; }
}

// The TLS socket is handed to HTTP only after its certificate fingerprint matches.
// Operator credentials are never sent to an unverified local service.
async function pinnedRequest(config, path, token, method = 'GET', body = undefined) {
  const agent = new https.Agent({ keepAlive: false });
  agent.createConnection = (_options, callback) => {
    const socket = tls.connect({ host: '127.0.0.1', port: Number(config.url.port || 443), servername: 'localhost', rejectUnauthorized: false });
    let settled = false;
    const done = (error, connection) => { if (settled) return; settled = true; callback(error, connection); };
    socket.once('secureConnect', () => {
      const actual = socket.getPeerCertificate().fingerprint256;
      const expected = config.fingerprint;
      if (!actual || actual.length !== expected.length || !timingSafeEqual(Buffer.from(actual), Buffer.from(expected))) {
        socket.destroy(); done(new AgentError(502, 'agent_tls_pin_mismatch')); return;
      }
      done(null, socket);
    });
    socket.once('error', () => done(new AgentError(502, 'agent_unavailable')));
  };
  const payload = body === undefined ? undefined : JSON.stringify(body);
  return new Promise((resolve, reject) => {
    const request = https.request(new URL(path, config.url), { agent, method, timeout: 5_000,
      headers: { 'X-Honey-Token': token, Origin: config.url.origin,
        ...(payload === undefined ? {} : { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) }) } }, (response) => {
      let size = 0; const chunks = [];
      response.on('data', (chunk) => {
        size += chunk.length;
        if (size > RESPONSE_LIMIT) request.destroy(new AgentError(502, 'agent_response_too_large'));
        else chunks.push(chunk);
      });
      response.on('end', () => {
        if (response.statusCode !== 200 && response.statusCode !== 202) {
          const status = [400, 401, 403, 404, 409, 503].includes(response.statusCode) ? response.statusCode : 502;
          const code = ({ 400: 'agent_rejected_input', 401: 'agent_unauthorized', 403: 'agent_forbidden',
            404: 'agent_contract_unavailable', 409: 'agent_mode_or_grant_conflict', 503: 'agent_unavailable' })[status] ?? 'agent_rejected_action';
          reject(new AgentError(status, code)); return;
        }
        try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
        catch { reject(new AgentError(502, 'agent_response_invalid')); }
      });
    });
    request.on('timeout', () => request.destroy(new AgentError(504, 'agent_timeout')));
    request.on('error', reject);
    request.end(payload);
  });
}

export function createAgentControl(rawConfig, transport = pinnedRequest) {
  const config = agentConfig(rawConfig);
  if (!config) return null;
  const request = (path, token, method, body) => transport(config, path, token, method, body);
  return {
    async authenticate(token) {
      if (typeof token !== 'string' || token.length < 32 || token.length > 256 || /\s/.test(token)) throw new AgentError(401, 'agent_unauthorized');
      await request('/api/bans', token);
      return true;
    },
    grants: (token) => request('/api/enforcement/grants', token),
    counters: (token) => request('/api/xdp/drop-totals', token),
    interfaces: (token) => request('/api/ifaces', token),
    decision(token, ip) {
      if (typeof ip !== 'string' || !isIP(ip)) throw new AgentError(400, 'invalid_source_ip');
      return request(`/api/enforcement/decision?ip=${encodeURIComponent(ip)}`, token);
    },
    history(token, ip, limit = 25) {
      if (typeof ip !== 'string' || !isIP(ip) || !Number.isInteger(limit) || limit < 1 || limit > 100) throw new AgentError(400, 'invalid_history_query');
      return request(`/api/enforcement/history?ip=${encodeURIComponent(ip)}&limit=${limit}`, token);
    },
    preview(token, { ip, ttl_seconds }) {
      if (typeof ip !== 'string' || !isIP(ip) || !Number.isInteger(ttl_seconds) || ttl_seconds < 30 || ttl_seconds > 86400) {
        throw new AgentError(400, 'invalid_preview_request');
      }
      return request('/api/enforcement/preview', token, 'POST', { ip, ttl_seconds });
    },
    async contract(token, requireGrantCreation = false) {
      const result = await request('/api/enforcement/contract', token);
      if (result?.contract_version !== 1 || typeof result.operator_grants !== 'boolean' || result.scoped_release !== true || result.uee_ready !== true) {
        throw new AgentError(409, 'agent_contract_incompatible');
      }
      if (requireGrantCreation && result.operator_grants !== true) throw new AgentError(403, 'operator_grants_unavailable');
      return result;
    },
    async ban(token, { ip, ttl_seconds }) {
      if (typeof ip !== 'string' || !isIP(ip) || !Number.isInteger(ttl_seconds) || ttl_seconds < 30 || ttl_seconds > 86400) throw new AgentError(400, 'invalid_bounded_ban');
      await this.contract(token, true);
      return request('/api/enforcement/operator-grants', token, 'POST', { ip, ttl_seconds, reason: 'firewall console operator' });
    },
    async release(token, { ip, grant_id }) {
      if (typeof ip !== 'string' || !isIP(ip) || typeof grant_id !== 'string' || !/^firewall-console:[a-f0-9]{32}$/.test(grant_id)) {
        throw new AgentError(400, 'invalid_operator_grant');
      }
      await this.contract(token);
      return request('/api/enforcement/operator-grants/release', token, 'POST', { ip, grant_id });
    },
    async returnToTest(token, { confirm }) {
      if (confirm !== 'RETURN TO TEST') throw new AgentError(400, 'confirmation_required');
      return request('/api/mode', token, 'POST', { mode: 'TEST' });
    },
  };
}

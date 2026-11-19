import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { realpathSync } from 'node:fs';
import { dirname, isAbsolute, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { hostname } from 'node:os';
import { createFirewallLab, BASE_POLICY } from './firewall.mjs';
import { loadLocalCredentials } from './local-credentials.mjs';
import { collectKernelTelemetry } from './kernel-telemetry.mjs';
import { inspectConnection } from './connection-inspector.mjs';
import { createKernelHistory } from './kernel-history.mjs';
import { createAgentOverview } from './agent-overview.mjs';
import { AgentError, createAgentControl } from './agent-control.mjs';
import { createOperatorAccount } from './operator-account.mjs';
import { canonicalAddress, explainHostDecision } from './decision-explorer.mjs';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const MAX_JSON = 65_536;
const SESSION_COOKIE = 'hm_lab_session';
const SESSION_MS = 30 * 24 * 60 * 60 * 1_000;
const HOST_SESSION_MS = 15 * 60 * 1_000;
const HOST_COOKIE = 'hm_host_session';

class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

function authorized(header, expected, expiresAt) {
  if (expiresAt && Date.now() >= Date.parse(expiresAt)) return false;
  if (typeof header !== 'string' || !header.startsWith('Bearer ')) return false;
  const actual = Buffer.from(header.slice(7));
  const wanted = Buffer.from(expected);
  return actual.length === wanted.length && timingSafeEqual(actual, wanted);
}

function sessionExpiresAt(adminTokenExpiresAt) {
  const credentialExpiry = adminTokenExpiresAt ? Date.parse(adminTokenExpiresAt) : Infinity;
  return Math.min(credentialExpiry, Date.now() + SESSION_MS);
}

function sessionSignature(expiresAt, adminToken) {
  return createHmac('sha256', adminToken).update(`hm-lab-session-v1:${expiresAt}`).digest('hex');
}

function sessionCookie(value, maxAge) {
  return `${SESSION_COOKIE}=${value}; HttpOnly; SameSite=Strict; Path=/api; Max-Age=${maxAge}`;
}

function hostCookie(value, maxAge) {
  return `${HOST_COOKIE}=${value}; HttpOnly; SameSite=Strict; Path=/api; Max-Age=${maxAge}`;
}

function cookieValue(header, name) {
  return header?.split(';').map((part) => part.trim()).find((part) => part.startsWith(`${name}=`))?.slice(name.length + 1);
}

function sessionExpiry(cookieHeader, adminToken, adminTokenExpiresAt) {
  if (!cookieHeader || (adminTokenExpiresAt && Date.now() >= Date.parse(adminTokenExpiresAt))) return null;
  const value = cookieHeader.split(';').map((part) => part.trim()).find((part) => part.startsWith(`${SESSION_COOKIE}=`))?.slice(SESSION_COOKIE.length + 1);
  const match = /^v1\.(\d{13})\.([a-f0-9]{64})$/.exec(value ?? '');
  if (!match || Date.now() >= Number(match[1]) || Number(match[1]) > sessionExpiresAt(adminTokenExpiresAt)) return null;
  const actual = Buffer.from(match[2], 'hex');
  const expected = Buffer.from(sessionSignature(match[1], adminToken), 'hex');
  return timingSafeEqual(actual, expected) ? Number(match[1]) : null;
}

async function readBody(request, limit = MAX_JSON) {
  if (Number(request.headers['content-length']) > limit) throw new HttpError(413, 'body_too_large');
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > limit) throw new HttpError(413, 'body_too_large');
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

function parseJson(bytes) {
  try {
    const value = JSON.parse(bytes.toString('utf8'));
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error();
    return value;
  } catch { throw new HttpError(400, 'invalid_json'); }
}

function respond(response, status, body, extraHeaders = {}) {
  const data = JSON.stringify(body);
  response.writeHead(status, { 'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store', 'x-content-type-options': 'nosniff',
    'x-frame-options': 'DENY', 'referrer-policy': 'no-referrer',
    'cross-origin-resource-policy': 'same-origin', ...extraHeaders });
  response.end(data);
}

export function createFirewallServer({ lab, adminToken, adminTokenExpiresAt, html, script, kernelTelemetry = collectKernelTelemetry, connectionInspector = inspectConnection, agentOverview = createAgentOverview(), agentControl = null, operatorAccount = null, hostActionsEnabled = false } = {}) {
  if (!lab || typeof adminToken !== 'string' || adminToken.length < 32) throw new TypeError('lab and adminToken required');
  const hostSessions = new Map();
  const kernelHistory = createKernelHistory(kernelTelemetry);
  const failedLogins = [];
  const failedPasswordChanges = [];
  const hostAudit = [];
  const scopedContract = async (token) => {
    if (!token) return { contract: null, status: 'token_missing' };
    if (typeof agentControl?.contract !== 'function') return { contract: null, status: 'upgrade_required' };
    try {
      const contract = await agentControl.contract(token);
      return contract?.contract_version === 1 && typeof contract?.operator_grants === 'boolean' && contract?.scoped_release === true && contract?.uee_ready === true
        ? { contract, status: 'supported' } : { contract: null, status: 'upgrade_required' };
    } catch (error) {
      return { contract: null, status: error?.message === 'agent_contract_unavailable' || error?.message === 'agent_contract_incompatible'
        ? 'upgrade_required' : error?.message === 'agent_unauthorized' ? 'token_rejected' : 'agent_unavailable' };
    }
  };
  const recordHostAction = (action, source, result) => {
    hostAudit.push({ at: new Date().toISOString(), action, source, result });
    if (hostAudit.length > 100) hostAudit.shift();
  };
  const server = createServer(async (request, response) => {
    try {
      if (request.headers.host !== `127.0.0.1:${server.address()?.port}`) {
        throw new HttpError(403, 'host_rejected');
      }
      const requestUrl = new URL(request.url, 'http://127.0.0.1');
      const path = requestUrl.pathname;
      if (request.method === 'GET' && (path === '/' || path === '/app.js')) {
        response.writeHead(200, { 'content-type': path === '/' ? 'text/html; charset=utf-8' : 'text/javascript; charset=utf-8',
          'cache-control': 'no-store', 'x-content-type-options': 'nosniff',
          'x-frame-options': 'DENY', 'referrer-policy': 'no-referrer',
          'content-security-policy': path === '/' ? "default-src 'none'; style-src 'unsafe-inline'; script-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'" : "default-src 'none'" });
        response.end(path === '/' ? html : script);
        return;
      }
      if (request.method === 'GET' && path === '/health') return respond(response, 200,
        { status: 'ok', scope: 'local_application_firewall_lab', host: hostname() });
      if (path === '/webhooks/observation' && request.method === 'POST') {
        if (!request.headers['content-type']?.startsWith('application/json')) throw new HttpError(415, 'json_required');
        const rawBody = await readBody(request);
        const result = lab.acceptWebhook({ rawBody,
          timestamp: request.headers['x-ng-timestamp'],
          eventId: request.headers['x-ng-event-id'],
          signature: request.headers['x-ng-signature'] });
        return respond(response, result.accepted ? 202 : 401, result);
      }
      if (!path.startsWith('/api/')) throw new HttpError(404, 'not_found');
      const sameOrigin = request.headers.origin === `http://127.0.0.1:${server.address()?.port}`;
      if (request.method === 'GET' && path === '/api/account/state') return respond(response, 200,
        { configured: operatorAccount?.configured() ?? false });
      if (request.method === 'POST' && path === '/api/account/setup') {
        if (!operatorAccount || !sameOrigin || !request.headers['content-type']?.startsWith('application/json')) throw new HttpError(403, 'account_setup_rejected');
        const body = parseJson(await readBody(request));
        const bootstrapValid = authorized(`Bearer ${body.bootstrap_token ?? ''}`, adminToken, adminTokenExpiresAt);
        try {
          const session = await operatorAccount.setup(bootstrapValid, body.username, body.password);
          return respond(response, 200, { username: 'admin', expires_at: new Date(session.expiresAt).toISOString(), token_saved: false },
            { 'set-cookie': session.cookie });
        } catch (error) { throw new HttpError(error.message === 'account_already_configured' ? 409 : 400, error.message); }
      }
      if (request.method === 'POST' && path === '/api/account/session') {
        if (!operatorAccount || !sameOrigin || !request.headers['content-type']?.startsWith('application/json')) throw new HttpError(403, 'account_login_rejected');
        const recent = failedLogins.filter((at) => at > Date.now() - 60_000);
        failedLogins.splice(0, failedLogins.length, ...recent);
        if (failedLogins.length >= 5) throw new HttpError(429, 'login_rate_limited');
        const body = parseJson(await readBody(request));
        failedLogins.push(Date.now());
        try {
          const session = await operatorAccount.login(body.username, body.password);
          failedLogins.length = 0;
          return respond(response, 200, { username: 'admin', expires_at: new Date(session.expiresAt).toISOString(),
            token_saved: operatorAccount.agentTokenSaved() }, { 'set-cookie': session.cookie });
        } catch { throw new HttpError(401, 'invalid_credentials'); }
      }
      const accountSession = operatorAccount?.session(request.headers.cookie) ?? null;
      if (path === '/api/account/session' && request.method === 'GET') {
        if (!accountSession) throw new HttpError(401, 'operator_session_required');
        const renewed = operatorAccount.renew(accountSession);
        return respond(response, 200, { username: 'admin', expires_at: new Date(renewed?.expiresAt ?? accountSession.expiresAt).toISOString(),
          token_saved: operatorAccount.agentTokenSaved() }, renewed ? { 'set-cookie': renewed.cookie } : {});
      }
      if (path === '/api/account/agent-token' && request.method === 'POST') {
        if (!accountSession || !sameOrigin || !agentControl || !request.headers['content-type']?.startsWith('application/json')) throw new HttpError(403, 'operator_session_required');
        const body = parseJson(await readBody(request));
        await operatorAccount.saveAgentToken(accountSession, body.token, agentControl);
        return respond(response, 200, { token_saved: true });
      }
      if (path === '/api/account/password' && request.method === 'POST') {
        if (!accountSession || !sameOrigin || !request.headers['content-type']?.startsWith('application/json')) throw new HttpError(403, 'operator_session_required');
        const recent = failedPasswordChanges.filter((at) => at > Date.now() - 60_000);
        failedPasswordChanges.splice(0, failedPasswordChanges.length, ...recent);
        if (failedPasswordChanges.length >= 5) throw new HttpError(429, 'password_change_rate_limited');
        const body = parseJson(await readBody(request));
        failedPasswordChanges.push(Date.now());
        try {
          const session = await operatorAccount.changePassword(accountSession, body.current_password, body.new_password);
          failedPasswordChanges.length = 0;
          return respond(response, 200, { changed: true, expires_at: new Date(session.expiresAt).toISOString() },
            { 'set-cookie': session.cookie });
        } catch { throw new HttpError(400, 'password_change_rejected'); }
      }
      if (request.method === 'POST' && path === '/api/session') {
        if (operatorAccount?.configured()) throw new HttpError(409, 'use_operator_account');
        if (!sameOrigin) throw new HttpError(403, 'origin_rejected');
        if (!request.headers['content-type']?.startsWith('application/json')) throw new HttpError(415, 'json_required');
        const body = parseJson(await readBody(request));
        if (!authorized(`Bearer ${body.token ?? ''}`, adminToken, adminTokenExpiresAt)) throw new HttpError(401, 'unauthorized');
        const expiresAt = sessionExpiresAt(adminTokenExpiresAt);
        const maxAge = Math.max(0, Math.floor((expiresAt - Date.now()) / 1_000));
        const value = `v1.${expiresAt}.${sessionSignature(expiresAt, adminToken)}`;
        return respond(response, 200, { expires_at: new Date(expiresAt).toISOString(), renewal: 'restart_after_expiry' },
          { 'set-cookie': sessionCookie(value, maxAge) });
      }
      const bearerAllowed = !operatorAccount?.configured() && authorized(request.headers.authorization, adminToken, adminTokenExpiresAt);
      const cookieExpiry = operatorAccount?.configured() ? null : sessionExpiry(request.headers.cookie, adminToken, adminTokenExpiresAt);
      const cookieAllowed = cookieExpiry !== null;
      if (!bearerAllowed && !cookieAllowed && !accountSession) throw new HttpError(401, 'unauthorized');
      if (request.method === 'GET' && path === '/api/session') return respond(response, 200,
        { expires_at: new Date(accountSession?.expiresAt ?? cookieExpiry ?? sessionExpiresAt(adminTokenExpiresAt)).toISOString(),
          renewal: accountSession ? 'rolling_operator_session' : 'restart_after_expiry' });
      if (request.method === 'DELETE' && path === '/api/session') {
        if (!sameOrigin) throw new HttpError(403, 'origin_rejected');
        hostSessions.delete(cookieValue(request.headers.cookie, HOST_COOKIE));
        if (accountSession) await operatorAccount.logout();
        return respond(response, 200, { signed_out: true }, { 'set-cookie': [sessionCookie('', 0), hostCookie('', 0),
          ...(operatorAccount ? [operatorAccount.clearCookie()] : [])] });
      }
      if (path.startsWith('/api/host/')) {
        if (!agentControl) throw new HttpError(503, 'host_controls_unavailable');
        if (request.method === 'POST' && path === '/api/host/session') {
          if (operatorAccount?.configured()) throw new HttpError(409, 'use_operator_account');
          if (!sameOrigin || !request.headers['content-type']?.startsWith('application/json')) throw new HttpError(403, 'host_login_rejected');
          const body = parseJson(await readBody(request));
          await agentControl.authenticate(body.token);
          const id = randomBytes(32).toString('hex');
          const expiresAt = Date.now() + HOST_SESSION_MS;
          for (const [key, session] of hostSessions) if (session.expiresAt <= Date.now()) hostSessions.delete(key);
          if (hostSessions.size >= 4) hostSessions.delete(hostSessions.keys().next().value);
          hostSessions.set(id, { token: body.token, expiresAt });
          const expiryTimer = setTimeout(() => hostSessions.delete(id), HOST_SESSION_MS);
          expiryTimer.unref();
          return respond(response, 200, { expires_at: new Date(expiresAt).toISOString(), actions_enabled: hostActionsEnabled }, { 'set-cookie': hostCookie(id, HOST_SESSION_MS / 1_000) });
        }
        const id = cookieValue(request.headers.cookie, HOST_COOKIE);
        const session = hostSessions.get(id);
        if (request.method === 'DELETE' && path === '/api/host/session') {
          if (!sameOrigin) throw new HttpError(403, 'origin_rejected');
          hostSessions.delete(id);
          return respond(response, 200, { signed_out: true }, { 'set-cookie': hostCookie('', 0) });
        }
        const accountToken = accountSession ? operatorAccount.agentToken(accountSession) : null;
        const legacySession = !operatorAccount?.configured() && session?.expiresAt > Date.now() ? session : null;
        const operatorToken = accountToken ?? legacySession?.token;
        const operatorExpiresAt = accountToken ? accountSession.expiresAt : legacySession?.expiresAt;
        if (request.method === 'GET' && path === '/api/host/session' && accountSession) {
          const { contract, status } = await scopedContract(accountToken);
          return respond(response, 200, { expires_at: new Date(accountSession.expiresAt).toISOString(),
            token_saved: Boolean(accountToken), actions_enabled: hostActionsEnabled,
            scoped_actions_enabled: Boolean(hostActionsEnabled && contract),
            grant_creation_entitled: contract?.operator_grants === true,
            ban_enabled: Boolean(hostActionsEnabled && contract?.operator_grants === true && contract?.xdp_attached === true && ['ENFORCE', 'LOCKDOWN'].includes(contract?.mode)),
            contract_status: status, agent_version: contract?.agent_version ?? null });
        }
        if (!operatorToken) { hostSessions.delete(id); throw new HttpError(401, 'host_operator_session_required'); }
        if (request.method === 'GET' && path === '/api/host/session') {
          const { contract, status } = await scopedContract(operatorToken);
          return respond(response, 200, { expires_at: new Date(operatorExpiresAt).toISOString(), token_saved: true,
            actions_enabled: hostActionsEnabled,
            scoped_actions_enabled: Boolean(hostActionsEnabled && contract),
            grant_creation_entitled: contract?.operator_grants === true,
            ban_enabled: Boolean(hostActionsEnabled && contract?.operator_grants === true && contract?.xdp_attached === true && ['ENFORCE', 'LOCKDOWN'].includes(contract?.mode)),
            contract_status: status, agent_version: contract?.agent_version ?? null });
        }
        if (request.method === 'GET' && path === '/api/host/grants') return respond(response, 200, await agentControl.grants(operatorToken));
        if (request.method === 'GET' && path === '/api/host/decision') {
          const ip = canonicalAddress(requestUrl.searchParams.get('ip'));
          if (!ip) throw new HttpError(400, 'invalid_source_ip');
          if (typeof agentControl.decision === 'function') {
            try {
              const direct = await agentControl.decision(operatorToken, ip);
              if (direct?.ip !== ip || !Array.isArray(direct.grants) || typeof direct.sampled_at !== 'string' ||
                  typeof direct.kernel_applied !== 'boolean' || !['kernel_block_reported', 'release_override_active',
                    'grant_pending_or_not_applied', 'no_active_uee_grant'].includes(direct.outcome)) {
                throw new AgentError(502, 'agent_decision_invalid');
              }
              const counters = typeof agentControl.counters === 'function'
                ? await agentControl.counters(operatorToken).catch(() => null) : null;
              const outcomes = { kernel_block_reported: 'kernel_block_confirmed',
                release_override_active: 'override_active', no_active_uee_grant: 'no_active_grant' };
              return respond(response, 200, { ...direct, outcome: outcomes[direct.outcome] ?? direct.outcome,
                captured_at: direct.sampled_at, host_mode: direct.mode, global_xdp_drop_totals: counters,
                proposed_scope: direct.scope });
            } catch (error) {
              if (!(error instanceof AgentError) || error.status !== 404) throw error;
            }
          }
          const snapshot = await agentControl.grants(operatorToken);
          const [contract, counters] = await Promise.allSettled([
            agentControl.contract?.(operatorToken), agentControl.counters?.(operatorToken),
          ]);
          return respond(response, 200, explainHostDecision(ip, snapshot,
            contract.status === 'fulfilled' ? contract.value : null,
            counters.status === 'fulfilled' ? counters.value : null));
        }
        if (request.method === 'GET' && path === '/api/host/history') {
          const ip = canonicalAddress(requestUrl.searchParams.get('ip'));
          if (!ip) throw new HttpError(400, 'invalid_source_ip');
          if (typeof agentControl.history !== 'function') throw new HttpError(409, 'agent_upgrade_required');
          try { return respond(response, 200, await agentControl.history(operatorToken, ip, 25)); }
          catch (error) { if (error instanceof AgentError && error.status === 404) throw new HttpError(409, 'agent_upgrade_required'); throw error; }
        }
        if (request.method === 'GET' && path === '/api/host/counters') return respond(response, 200, await agentControl.counters(operatorToken));
        if (request.method === 'GET' && path === '/api/host/interfaces') return respond(response, 200, await agentControl.interfaces(operatorToken));
        if (request.method === 'GET' && path === '/api/host/audit') return respond(response, 200, hostAudit);
        if (request.method !== 'POST' || !sameOrigin || !request.headers['content-type']?.startsWith('application/json')) throw new HttpError(403, 'host_action_rejected');
        if (path === '/api/host/preview') {
          if (typeof agentControl.preview !== 'function') throw new HttpError(409, 'agent_upgrade_required');
          const body = parseJson(await readBody(request));
          try { return respond(response, 200, await agentControl.preview(operatorToken, body)); }
          catch (error) { if (error instanceof AgentError && error.status === 404) throw new HttpError(409, 'agent_upgrade_required'); throw error; }
        }
        if (!hostActionsEnabled) throw new HttpError(503, 'host_actions_not_qualified');
        const body = parseJson(await readBody(request));
        if (path === '/api/host/ban' || path === '/api/host/release' || path === '/api/host/test-mode') {
          const action = path === '/api/host/ban' ? 'temporary_block' : path === '/api/host/release' ? 'scoped_release' : 'return_to_test';
          const source = action !== 'return_to_test' && typeof body.ip === 'string' ? body.ip.slice(0, 45) : null;
          try {
            if (action !== 'return_to_test') {
              const { contract, status } = await scopedContract(operatorToken);
              if (!contract || (action === 'temporary_block' && (contract.operator_grants !== true || contract.xdp_attached !== true || !['ENFORCE', 'LOCKDOWN'].includes(contract.mode)))) throw new AgentError(409, status === 'supported' ? 'scoped_agent_mode_unavailable' : status);
            }
            const result = action === 'temporary_block' ? await agentControl.ban(operatorToken, body)
              : action === 'scoped_release' ? await agentControl.release(operatorToken, body) : await agentControl.returnToTest(operatorToken, body);
            recordHostAction(action, source, 'accepted');
            return respond(response, 200, result);
          } catch (error) {
            recordHostAction(action, source, error instanceof AgentError ? error.message : 'agent_error');
            throw error;
          }
        }
        throw new HttpError(404, 'not_found');
      }
      if (request.method === 'GET' && path === '/api/status') return respond(response, 200,
        { ...lab.status(), admin_token_expires_at: adminTokenExpiresAt ?? null });
      if (request.method === 'GET' && path === '/api/kernel/telemetry') {
        const query = requestUrl.searchParams;
        const offset = Number(query.get('offset') ?? 0);
        const limit = Number(query.get('limit') ?? 100);
        try {
          return respond(response, 200, await kernelTelemetry({ protocol: query.get('protocol') ?? '', state: query.get('state') ?? '', search: query.get('search') ?? '', sort: query.get('sort') ?? 'state', offset, limit }));
        } catch (error) {
          if (error.code === 'EACCES' || error.code === 'EPERM') throw new HttpError(503, 'host_telemetry_permission_denied');
          throw error;
        }
      }
      if (request.method === 'GET' && path === '/api/kernel/history') return respond(response, 200, kernelHistory.snapshot());
      if (request.method === 'GET' && path === '/api/kernel/connection') {
        const query = requestUrl.searchParams;
        return respond(response, 200, await connectionInspector({ inode: query.get('inode'), remote_address: query.get('remote_address'),
          remote_port: Number(query.get('remote_port')), resolveHost: query.get('resolve_host') === '1' }));
      }
      if (request.method === 'GET' && path === '/api/agent/overview') return respond(response, 200, await agentOverview());
      if (request.method !== 'POST') throw new HttpError(405, 'method_not_allowed');
      if (!request.headers['content-type']?.startsWith('application/json')) throw new HttpError(415, 'json_required');
      const origin = request.headers.origin;
      if (cookieAllowed && !bearerAllowed && !sameOrigin) throw new HttpError(403, 'origin_rejected');
      if (origin && !sameOrigin) throw new HttpError(403, 'origin_rejected');
      const body = parseJson(await readBody(request));
      if (path === '/api/lab/attempt') return respond(response, 200, lab.syntheticAttempt(body.source_ip));
      if (path === '/api/lab/probe') return respond(response, 200, lab.probe(body.source_ip));
      if (path === '/api/lab/release') return respond(response, 200, { released: lab.release(body.source_ip) });
      if (path === '/api/review') return respond(response, 200, lab.review(body.proposed_policy));
      if (path === '/api/replay') return respond(response, 200, lab.replay(body.proposed_policy));
      throw new HttpError(404, 'not_found');
    } catch (error) {
      const status = error instanceof HttpError || error instanceof AgentError ? error.status : error instanceof TypeError || error instanceof RangeError ? 400 : 500;
      respond(response, status, { error: status === 500 ? 'internal_error' : error.message });
    }
  });
  server.requestTimeout = 10_000;
  server.headersTimeout = 5_000;
  server.on('listening', () => kernelHistory.start());
  server.on('close', () => kernelHistory.stop());
  return server;
}

if (process.argv[1] && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const port = Number(process.env.LAB_PORT ?? 8787);
  if (!Number.isInteger(port) || port < 1024 || port > 65_535) throw new Error('LAB_PORT must be 1024-65535');
  const stateDir = process.env.HM_CONSOLE_STATE_DIR ?? join(root, '.local');
  if (!isAbsolute(stateDir)) throw new Error('HM_CONSOLE_STATE_DIR must be an absolute path');
  const secrets = await loadLocalCredentials(join(stateDir, 'credentials.json'));
  const policy = { ...BASE_POLICY, mode: process.env.LAB_ENFORCE === '1' ? 'ENFORCE' : 'OBSERVE' };
  const lab = createFirewallLab({ policy, webhookSecret: secrets.webhookSecret });
  const [html, script] = await Promise.all([
    readFile(join(root, 'src', 'index.html'), 'utf8'),
    readFile(join(root, 'src', 'app.js'), 'utf8'),
  ]);
  let agentConfig;
  try { agentConfig = JSON.parse(await readFile(join(stateDir, 'agent-public.json'), 'utf8')); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
  const server = createFirewallServer({ lab, adminToken: secrets.adminToken,
    adminTokenExpiresAt: secrets.adminTokenExpiresAt, html, script,
    agentOverview: createAgentOverview(agentConfig), agentControl: createAgentControl(agentConfig),
    operatorAccount: await createOperatorAccount(join(stateDir, 'operator-account.json')),
    hostActionsEnabled: process.env.HM_HOST_ACTIONS_ENABLED === '1' });
  server.listen(port, '127.0.0.1', () => {
    process.stdout.write(`Network Decode Firewall Console: http://127.0.0.1:${port}\nNode Guard lab mode: ${policy.mode}; synthetic fixtures only. Host writes: ${process.env.HM_HOST_ACTIONS_ENABLED === '1' ? 'disposable-lab candidate enabled' : 'closed'}.\nThe local admin token expires ${secrets.adminTokenExpiresAt}. It is separate from customer licenses.\n`);
  });
}

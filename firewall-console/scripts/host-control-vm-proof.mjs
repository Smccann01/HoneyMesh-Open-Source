#!/usr/bin/env node
// Disposable VM only. Invoke as root after a signed HoneyMesh Core install.
// Prints assertions and counts, never the agent or local lab credential.
import { readFile } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import tls from 'node:tls';
import { isIP } from 'node:net';
import { createFirewallLab } from '../src/firewall.mjs';
import { createFirewallServer } from '../src/server.mjs';
import { createAgentControl } from '../src/agent-control.mjs';

const [phase, source] = process.argv.slice(2);
if (!['test-mode', 'ban', 'ban-long', 'ban-reboot', 'release', 'expired', 'return-test'].includes(phase) || !isIP(source)) {
  throw new Error('usage: host-control-vm-proof.mjs test-mode|ban|ban-long|ban-reboot|release|expired|return-test <test-client-ip>');
}

const ca = await readFile('/etc/honeymesh/certs/ca/ca.crt');
const fingerprint = await new Promise((resolve, reject) => {
  const socket = tls.connect({ host: '127.0.0.1', port: 8443, ca, rejectUnauthorized: true });
  socket.once('secureConnect', () => { resolve(socket.getPeerCertificate().fingerprint256); socket.end(); });
  socket.once('error', reject);
  socket.setTimeout(5_000, () => socket.destroy(new Error('agent_tls_timeout')));
});
const agentControl = createAgentControl({ url: 'https://127.0.0.1:8443', fingerprint_sha256: fingerprint });
const operatorToken = JSON.parse(await readFile('/var/lib/honeymesh/runtime-state.json', 'utf8')).admin_token;
if (typeof operatorToken !== 'string' || operatorToken.length < 32) throw new Error('missing_agent_operator_token');
const labToken = randomBytes(32).toString('hex');
const server = createFirewallServer({ lab: createFirewallLab({ webhookSecret: randomBytes(32).toString('hex') }),
  adminToken: labToken, html: '', script: '', agentControl, hostActionsEnabled: true,
  agentOverview: async () => ({ connected: true }) });
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const base = `http://127.0.0.1:${server.address().port}`;
const post = (path, cookie, body) => fetch(`${base}${path}`, { method: 'POST',
  headers: { origin: base, cookie, 'content-type': 'application/json' }, body: JSON.stringify(body) });
try {
  const lab = await post('/api/session', '', { token: labToken });
  if (lab.status !== 200) throw new Error('lab_login_failed');
  const labCookie = lab.headers.get('set-cookie').split(';')[0];
  if ((await fetch(`${base}/api/host/grants`, { headers: { cookie: labCookie } })).status !== 401) throw new Error('host_auth_boundary_failed');
  const login = await post('/api/host/session', labCookie, { token: operatorToken });
  if (login.status !== 200) throw new Error('operator_login_failed');
  const cookie = `${labCookie}; ${login.headers.get('set-cookie').split(';')[0]}`;
  const grantsBefore = await fetch(`${base}/api/host/grants`, { headers: { cookie } });
  const counters = await fetch(`${base}/api/host/counters`, { headers: { cookie } });
  const interfaces = await fetch(`${base}/api/host/interfaces`, { headers: { cookie } });
  if ([grantsBefore, counters, interfaces].some((response) => response.status !== 200)) throw new Error('protected_read_failed');
  const before = await grantsBefore.json();
  if (!Array.isArray(before)) throw new Error('grant_shape_invalid');
  const stateOf = (entry) => entry?.state ?? entry?.State ?? {};
  const grantsOf = (entry) => entry?.grants ?? entry?.Grants ?? [];
  const bySource = (items) => items.find((entry) => stateOf(entry).IP === source);
  const operatorId = (grant) => (grant?.Owner ?? grant?.owner ?? {}).ID;
  const operatorGrants = (entry) => grantsOf(entry).filter((grant) =>
    (grant.Owner ?? grant.owner)?.Kind === 'local' && /^firewall-console:[a-f0-9]{32}$/.test(operatorId(grant) ?? ''));
  let result;
  if (phase === 'test-mode') {
    result = await post('/api/host/ban', cookie, { ip: source, ttl_seconds: 60 });
    if (result.status !== 409) throw new Error(`test_mode_should_reject_ban_${result.status}`);
  } else if (phase === 'ban' || phase === 'ban-long' || phase === 'ban-reboot') {
    result = await post('/api/host/ban', cookie, { ip: source, ttl_seconds: phase === 'ban-reboot' ? 300 : phase === 'ban-long' ? 120 : 60 });
    const created = await result.json();
    if (result.status !== 200 || created.kernel_reconciled !== true || !/^firewall-console:[a-f0-9]{32}$/.test(created.grant_id ?? '')) {
      throw new Error(`operator_grant_failed_${result.status}`);
    }
    const after = await (await fetch(`${base}/api/host/grants`, { headers: { cookie } })).json();
    if (stateOf(bySource(after)).KernelApplied !== true || !operatorGrants(bySource(after)).some((grant) => operatorId(grant) === created.grant_id)) {
      throw new Error('operator_grant_or_kernel_apply_missing');
    }
  } else if (phase === 'release') {
    const owner = operatorGrants(bySource(before))[0];
    if (!owner) throw new Error('operator_grant_missing_before_release');
    const id = operatorId(owner);
    result = await post('/api/host/release', cookie, { ip: source, grant_id: id });
    const released = await result.json();
    if (result.status !== 200 || released.grant_removed !== true || released.kernel_reconciled !== true) throw new Error(`scoped_release_failed_${result.status}`);
    const after = await (await fetch(`${base}/api/host/grants`, { headers: { cookie } })).json();
    if (operatorGrants(bySource(after)).some((grant) => operatorId(grant) === id)) throw new Error('released_operator_grant_still_active');
  } else if (phase === 'expired') {
    if (operatorGrants(bySource(before)).length) throw new Error('operator_grant_still_active');
  } else {
    result = await post('/api/host/test-mode', cookie, { confirm: 'RETURN TO TEST' });
    if (result.status !== 200 || (await result.json()).mode !== 'TEST') throw new Error('return_to_test_failed');
  }
  const audit = await (await fetch(`${base}/api/host/audit`, { headers: { cookie } })).json();
  console.log(JSON.stringify({ phase, source, result: 'PASS', grants_before: before.length,
    audit_actions: audit.map((event) => ({ action: event.action, result: event.result })) }));
} finally {
  await new Promise((resolve) => server.close(resolve));
}

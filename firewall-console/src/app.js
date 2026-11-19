const $ = (selector) => document.querySelector(selector);
const output = $('#result');
let policy;
let toastTimer;
let sessionExpiresAt = null;
let kernelSnapshot = null;
let previousKernelSnapshot = null;
let kernelHistorySnapshot = null;
let kernelRefreshPending = false;
let connectionOffset = 0;
let selectedConnection = null;
let selectedConnectionSeenAt = null;
let selectedConnectionPresent = false;
const connectionInfoCache = new Map();
let hoverTicket = 0;
const CONNECTION_PAGE_SIZE = 100;
let hostExpiresAt = null;
let hostActionsEnabled = false;
let hostScopedActionsEnabled = false;
let hostBanEnabled = false;
let hostGrantAvailable = false;
let hostContractStatus = 'upgrade_required';
let hostTokenSaved = false;
let accountSignedIn = false;
let accountConfigured = null;
let agentMode = null;
let agentConnected = false;
let activePage = 'overview';
const pageCopy = {
  overview: ['Overview', 'Host protection and current operating state'],
  connections: ['Connections', 'Inspect the current Linux socket snapshot'],
  enforcement: ['Enforcement', 'Effective blocks and independently owned grants'],
  activity: ['Activity', 'Recent operator actions on this console'],
  interfaces: ['Interfaces', 'Linux interface traffic and HoneyMesh accounting'],
  lab: ['Lab tools', 'Synthetic application policy exercises'],
  settings: ['Settings', 'Local administrator and HoneyMesh operator access'],
};

function showPage(page, persist = true) {
  const next = !accountSignedIn && page !== 'settings' ? 'settings' : pageCopy[page] ? page : 'overview';
  activePage = next;
  for (const screen of document.querySelectorAll('[data-screen]')) screen.hidden = screen.dataset.screen !== next;
  for (const button of document.querySelectorAll('[data-nav]')) {
    const selected = button.dataset.nav === next;
    button.disabled = !accountSignedIn && button.dataset.nav !== 'settings';
    button.classList.toggle('active', selected);
    if (selected) button.setAttribute('aria-current', 'page'); else button.removeAttribute('aria-current');
  }
  $('#page-title').textContent = pageCopy[next][0];
  $('#page-subtitle').textContent = pageCopy[next][1];
  $('#mobile-menu-toggle').setAttribute('aria-expanded', 'false');
  $('.sidebar').classList.remove('open');
  if (persist && accountSignedIn && next !== 'settings') localStorage.setItem('firewall-page', next);
  if (next === 'activity' && accountSignedIn && hostTokenSaved) loadActivity().catch((error) => notify(error.message, true));
  if (next === 'enforcement' && accountSignedIn && hostTokenSaved) loadHostGrants().catch((error) => notify(error.message, true));
  if (next === 'interfaces' && accountSignedIn && hostTokenSaved) {
    loadXdpCounters().catch((error) => notify(error.message, true));
    loadAgentInterfaces().catch((error) => notify(error.message, true));
  }
}

function setBanner(message, error = false) {
  $('#status-banner').textContent = message;
  $('#status-banner').classList.toggle('error', error);
}

function notify(message, error = false) {
  const toast = $('#toast');
  toast.textContent = message;
  toast.classList.toggle('error', error);
  toast.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { toast.hidden = true; }, 6500);
}

async function call(path, body, quiet = false) {
  const response = await fetch(path, {
    method: body === undefined ? 'GET' : 'POST',
    headers: {
      ...(body === undefined ? {} : { 'content-type': 'application/json' }),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const data = await response.json();
  if (!response.ok) {
    if (response.status === 401 && path.startsWith('/api/host/')) { hostExpiresAt = null; hostTokenSaved = false; updateHostCountdown(); }
    else if (response.status === 401) { sessionExpiresAt = null; accountSignedIn = false; updateCountdown(); showPage('settings', false); }
    throw new Error(`${response.status}: ${data.error ?? 'request failed'}`);
  }
  if (!quiet) output.textContent = JSON.stringify(data, null, 2);
  return data;
}

function updateStatus(status) {
  policy = status.policy;
  $('#app-mode').textContent = policy.mode;
  $('#observation-count').textContent = String(status.recorded_observations);
  $('#restriction-count').textContent = String(status.active_restrictions?.length ?? 0);
  $('#top-mode').textContent = `${policy.mode} · local`;
  $('#top-mode').classList.toggle('live', policy.mode === 'ENFORCE');
  updateCountdown();
}

function updateCountdown() {
  const label = $('#unlock-state');
  if (!sessionExpiresAt) { label.textContent = accountConfigured === false ? 'Create the local administrator account to begin.' : 'Sign in with the local administrator password.'; return; }
  const remaining = Math.max(0, sessionExpiresAt - Date.now());
  if (remaining === 0) {
    label.textContent = 'Browser session expired. Sign in with the admin password; the saved HoneyMesh token remains configured.';
    $('#top-mode').textContent = 'Local · expired';
    return;
  }
  const days = Math.floor(remaining / 86_400_000);
  const hours = Math.floor((remaining % 86_400_000) / 3_600_000);
  const minutes = Math.floor((remaining % 3_600_000) / 60_000);
  const seconds = Math.floor((remaining % 60_000) / 1_000);
  label.textContent = `Admin signed in. Browser session renews while active; current expiry ${new Date(sessionExpiresAt).toLocaleString()} (in ${days}d ${hours}h ${minutes}m ${seconds}s).`;
}

function blockReadiness() {
  if (!accountSignedIn) return { ready: false, message: 'Sign in under Settings to manage this host.' };
  if (!hostTokenSaved || !hostExpiresAt || Date.now() >= hostExpiresAt) return { ready: false, message: 'Save a valid HoneyMesh operator token under Settings first.' };
  const blockers = [];
  if (!hostActionsEnabled) blockers.push('Console host writes are closed in this installation');
  if (hostContractStatus === 'supported' && !hostGrantAvailable) blockers.push('the local agent does not currently permit new operator grants');
  if (hostContractStatus === 'upgrade_required') blockers.push('the installed Core agent lacks scoped operator grants');
  else if (hostContractStatus === 'token_rejected') blockers.push('the agent rejected the saved operator token');
  else if (hostContractStatus === 'agent_unavailable' || !agentConnected) blockers.push('the agent is unavailable');
  if (agentMode === 'TEST') blockers.push('HoneyMesh is in TEST mode');
  if (!hostBanEnabled && blockers.length === 0) blockers.push('attached XDP and ENFORCE are required');
  return blockers.length ? { ready: false, message: `${blockers.join('; ')}. Open HoneyMesh SOC to review the installed agent.` }
    : { ready: true, message: 'Scoped operator block is available. Choose an exact source and a duration up to 24 hours, then confirm the request.' };
}

function updateBlockReadiness() {
  const readiness = blockReadiness();
  $('#host-ban').textContent = readiness.ready ? 'Apply temporary block' : 'Check block availability';
  $('#ban-readiness').textContent = readiness.message;
  $('#ban-readiness').classList.toggle('ready', readiness.ready);
  $('#detail-block').textContent = readiness.ready ? 'Request source block' : 'Check block availability';
  return readiness;
}

function updateHostCountdown() {
  const valid = hostTokenSaved && hostExpiresAt && Date.now() < hostExpiresAt;
  $('#host-unlock').disabled = !accountSignedIn;
  for (const button of document.querySelectorAll('[data-host-action]')) button.disabled = !valid ||
    (button.dataset.hostWrite === 'true' && !hostActionsEnabled) ||
    (button.dataset.hostBan === 'true' && !hostBanEnabled) ||
    (button.dataset.hostRelease === 'true' && !hostScopedActionsEnabled);
  if (!valid) { $('#host-session-state').textContent = accountSignedIn ? 'Account unlocked. Save the HoneyMesh token once to enable protected host reads.' : 'Sign in as the local administrator to unlock host reads.'; updateBlockReadiness(); updateConnectionControls(); return; }
  const writeState = !hostActionsEnabled ? 'Host writes closed pending VM qualification.'
    : hostContractStatus === 'upgrade_required' ? 'The installed agent needs the signed scoped-grant upgrade before operator writes.'
      : hostContractStatus === 'token_rejected' ? 'The HoneyMesh token was rejected; replace it in this panel.'
        : hostContractStatus === 'agent_unavailable' ? 'The pinned agent is unavailable; host writes are closed.'
      : !hostGrantAvailable ? 'Existing operator grants can be released; the local agent does not currently permit new operator grants.'
        : hostBanEnabled ? 'Scoped operator writes are available in this test run.' : 'Scoped release is available; blocks require attached XDP and ENFORCE.';
  $('#host-session-state').textContent = `HoneyMesh token saved. Admin browser access currently expires ${new Date(hostExpiresAt).toLocaleString()} and renews with use. ${writeState}`;
  updateBlockReadiness();
  updateConnectionControls();
}
setInterval(() => { updateCountdown(); updateHostCountdown(); }, 1_000);

async function loadAccountState() {
  const response = await fetch('/api/account/session');
  accountSignedIn = response.ok;
  if (accountSignedIn) {
    const data = await response.json();
    accountConfigured = true;
    sessionExpiresAt = Date.parse(data.expires_at);
    $('#account-setup').hidden = true;
    $('#account-login').hidden = true;
    $('#account-password-change').hidden = false;
    $('#sign-out').hidden = false;
    $('.settings-side').hidden = false;
    updateCountdown();
    await refresh();
    await restoreHostSession();
    showPage(localStorage.getItem('firewall-page') || 'overview', false);
    return;
  }
  const state = await (await fetch('/api/account/state')).json();
  accountConfigured = state.configured === true;
  sessionExpiresAt = null;
  $('#account-setup').hidden = accountConfigured;
  $('#account-login').hidden = !accountConfigured;
  $('#account-password-change').hidden = true;
  $('#sign-out').hidden = true;
  $('.settings-side').hidden = true;
  updateCountdown();
  updateHostCountdown();
  $('#top-agent-state').textContent = 'Sign in required';
  $('#side-agent-state').textContent = 'Sign in required';
  $('#top-mode').textContent = 'Locked';
  $('#top-mode').classList.remove('live');
  setBanner('Sign in to load protected host status and socket data.');
  showPage('settings', false);
}

async function setupAccount() {
  const bootstrap = $('#bootstrap-token').value.trim();
  const password = $('#account-new-password').value;
  if (!bootstrap || password.length < 16) throw new Error('Enter the bootstrap token and a password of at least 16 characters.');
  try {
    const response = await fetch('/api/account/setup', { method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ bootstrap_token: bootstrap, username: 'admin', password }) });
    const data = await response.json();
    if (!response.ok) throw new Error(`${response.status}: ${data.error ?? 'account setup failed'}`);
  } finally { $('#bootstrap-token').value = ''; $('#account-new-password').value = ''; }
  await loadAccountState();
}

async function loginAccount() {
  const password = $('#account-password').value;
  if (!password) throw new Error('Enter the admin password.');
  try {
    const response = await fetch('/api/account/session', { method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ username: 'admin', password }) });
    const data = await response.json();
    if (!response.ok) throw new Error(`${response.status}: ${data.error ?? 'sign-in failed'}`);
  } finally { $('#account-password').value = ''; }
  await loadAccountState();
}

async function changeAccountPassword() {
  const currentPassword = $('#account-current-password').value;
  const newPassword = $('#account-replacement-password').value;
  if (!currentPassword || newPassword.length < 16) throw new Error('Enter the current password and a new password of at least 16 characters.');
  try {
    const response = await fetch('/api/account/password', { method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }) });
    const data = await response.json();
    if (!response.ok) throw new Error(`${response.status}: ${data.error ?? 'password change failed'}`);
  } finally { $('#account-current-password').value = ''; $('#account-replacement-password').value = ''; }
  await loadAccountState();
}

async function restoreHostSession() {
  const response = await fetch('/api/host/session');
  if (!response.ok) { hostExpiresAt = null; hostTokenSaved = false; updateHostCountdown(); return; }
  const data = await response.json();
  hostExpiresAt = Date.parse(data.expires_at);
  hostTokenSaved = data.token_saved === true;
  hostActionsEnabled = data.actions_enabled === true;
  hostScopedActionsEnabled = data.scoped_actions_enabled === true;
  hostBanEnabled = data.ban_enabled === true;
  hostGrantAvailable = data.grant_creation_entitled === true;
  hostContractStatus = data.contract_status ?? 'upgrade_required';
  updateHostCountdown();
}

async function unlockHost() {
  if (!accountSignedIn) throw new Error('Sign in as the local administrator first.');
  const value = $('#host-token').value.trim();
  if (!value) throw new Error('Enter the HoneyMesh operator token.');
  try {
    await call('/api/account/agent-token', { token: value }, true);
    await restoreHostSession();
  } finally { $('#host-token').value = ''; }
}

function hostAction(action) {
  return async () => {
    const result = await action();
    if (result === undefined) return false;
    $('#host-result').textContent = JSON.stringify(result, null, 2);
    await restoreHostSession().catch(() => { hostBanEnabled = false; hostGrantAvailable = false; hostScopedActionsEnabled = false; updateHostCountdown(); });
    await refreshAgent().catch((error) => { $('#agent-note').textContent = `Agent status refresh failed: ${error.message}`; });
    return true;
  };
}

function renderHostGrants(items) {
  if (!Array.isArray(items)) throw new Error('The agent returned an invalid grant list.');
  const body = $('#host-grant-rows');
  body.replaceChildren();
  let count = 0;
  for (const item of items) {
    const state = item.State ?? item.state ?? {};
    const grants = item.Grants ?? item.grants ?? [];
    for (const grant of grants) {
      const owner = grant.Owner ?? grant.owner ?? {};
      const ip = grant.IP ?? grant.ip ?? state.IP ?? state.ip ?? '';
      const ownerId = owner.ID ?? owner.id ?? '';
      const ownerKind = owner.Kind ?? owner.kind ?? '';
      const expires = grant.ExpiresAt ?? grant.expires_at;
      const row = document.createElement('tr');
      for (const value of [ip, `${ownerKind} / ${ownerId}`, grant.Reason ?? grant.reason ?? 'Not provided', expires ? new Date(expires).toLocaleString() : 'Unknown',
        (state.KernelApplied ?? state.kernel_applied) === true ? 'Applied' : 'Pending / not applied']) {
        const cell = document.createElement('td'); cell.textContent = String(value); row.append(cell);
      }
      const action = document.createElement('td');
      if (ownerKind === 'local' && /^firewall-console:[a-f0-9]{32}$/.test(ownerId)) {
        const button = document.createElement('button');
        button.className = 'button secondary small'; button.textContent = 'Release this grant';
        button.dataset.hostAction = ''; button.dataset.hostRelease = 'true';
        button.disabled = !hostScopedActionsEnabled;
        button.addEventListener('click', run(async () => {
          if (!confirm(`Release only operator grant ${ownerId} for ${ip}? Other owners will remain active.`)) return false;
          const result = await call('/api/host/release', { ip, grant_id: ownerId }, true);
          $('#host-result').textContent = JSON.stringify(result, null, 2);
          await loadHostGrants();
        }, 'Scoped release requested; inspect the kernel state.'));
        action.append(button);
      } else { action.textContent = 'Owned elsewhere'; }
      row.append(action); body.append(row); count++;
    }
  }
  if (!count) {
    const cell = document.createElement('td'); cell.colSpan = 6; cell.className = 'empty'; cell.textContent = 'No active grants reported.';
    const row = document.createElement('tr'); row.append(cell); body.append(row);
  }
}

async function loadActivity() {
  const events = await call('/api/host/audit', undefined, true);
  const list = $('#activity-list');
  list.replaceChildren();
  if (!Array.isArray(events) || events.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'empty'; empty.textContent = 'No operator actions have been recorded in this console session.';
    list.append(empty); return events;
  }
  for (const event of [...events].reverse()) {
    const row = document.createElement('div'); row.className = 'activity-item';
    const when = document.createElement('small');
    const timestamp = event.at ?? event.timestamp ?? event.time;
    when.textContent = timestamp ? new Date(timestamp).toLocaleString() : 'Time unavailable';
    const action = document.createElement('strong');
    action.textContent = `${String(event.action ?? 'operator action').replaceAll('_', ' ')}${event.source ? ` · ${event.source}` : ''}`;
    const result = document.createElement('span'); result.textContent = event.result ?? 'Result unavailable';
    row.append(when, action, result); list.append(row);
  }
  return events;
}

async function loadXdpCounters() {
  const data = await call('/api/host/counters', undefined, true);
  $('#xdp-ipv4-packets').textContent = number.format(data.ipv4?.packets ?? 0);
  $('#xdp-ipv6-packets').textContent = number.format(data.ipv6?.packets ?? 0);
  $('#xdp-ipv4-bytes').textContent = `${size(data.ipv4?.bytes ?? 0)} dropped`;
  $('#xdp-ipv6-bytes').textContent = `${size(data.ipv6?.bytes ?? 0)} dropped`;
  $('#xdp-reset').textContent = data.reset === 'agent_start' ? 'Agent start' : data.reset ?? 'Unknown';
  $('#interface-result').textContent = JSON.stringify(data, null, 2);
  return data;
}

async function loadAgentInterfaces() {
  const data = await call('/api/host/interfaces', undefined, true);
  if (!Array.isArray(data)) throw new Error('The agent returned an invalid interface list.');
  const rows = data.map((item) => ({ name: item.name ?? '', ips: item.ips ?? '', mode: item.mode ?? 'Unknown',
    up: item.is_up ? 'Yes' : 'No', selected: item.is_set ? 'Yes' : 'No' }));
  showRows('#agent-interface-rows', rows, ['name', 'ips', 'mode', 'up', 'selected'], 'No agent interfaces reported.');
  $('#interface-result').textContent = JSON.stringify(data, null, 2);
  return data;
}

async function loadHostGrants() {
  const result = await call('/api/host/grants', undefined, true);
  renderHostGrants(result);
  return result;
}

function run(action, success = 'Action completed. Details are in Operation result below.') {
  return async () => {
    try { if (await action() !== false) notify(success); }
    catch (error) { output.textContent = error.message; notify(error.message, true); }
  };
}

function showRows(selector, rows, keys, empty) {
  const body = $(selector);
  body.replaceChildren();
  if (!rows.length) {
    const cell = document.createElement('td'); cell.colSpan = keys.length; cell.className = 'empty'; cell.textContent = empty;
    const row = document.createElement('tr'); row.append(cell); body.append(row); return;
  }
  for (const record of rows) {
    const row = document.createElement('tr');
    for (const key of keys) { const cell = document.createElement('td'); cell.textContent = String(record[key]); row.append(cell); }
    body.append(row);
  }
}

function normalizedAddress(value) {
  try {
    const address = new URL(value.includes(':') ? `http://[${value}]/` : `http://${value}/`).hostname.replace(/^\[|\]$/g, '');
    const mapped = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i.exec(address);
    if (!mapped) return address;
    return [mapped[1], mapped[2]].flatMap((group) => [parseInt(group, 16) >> 8, parseInt(group, 16) & 255]).join('.');
  }
  catch { return value; }
}

function selectedConnectionIsCurrent() {
  return selectedConnection && selectedConnectionPresent && selectedConnectionSeenAt && Date.now() - Date.parse(selectedConnectionSeenAt) < 30_000 &&
    selectedConnection.remote_port > 0 && !/^0+(?::0+)*$/.test(selectedConnection.remote_address);
}

function updateConnectionControls() {
  const current = Boolean(selectedConnectionIsCurrent());
  const hostReady = hostTokenSaved && hostExpiresAt && Date.now() < hostExpiresAt;
  $('#detail-block').disabled = !current;
  $('#detail-grants').disabled = !current || !hostReady;
  $('#detail-history').disabled = !current || !hostReady;
  $('#detail-use-ip').disabled = !current;
  $('#detail-copy').disabled = !current;
}

async function loadConnectionInfo(record, resolveHost = false) {
  if (!record?.inode || !record.remote_address) return null;
  const key = `${record.inode}:${record.remote_address}:${record.remote_port}`;
  const cached = connectionInfoCache.get(key);
  if (!resolveHost && cached && Date.now() - cached.at < 15_000) return cached.data;
  const query = new URLSearchParams({ inode: record.inode, remote_address: record.remote_address,
    remote_port: String(record.remote_port), ...(resolveHost ? { resolve_host: '1' } : {}) });
  const data = await call(`/api/kernel/connection?${query}`, undefined, true);
  connectionInfoCache.set(key, { at: Date.now(), data });
  if (connectionInfoCache.size > 200) connectionInfoCache.delete(connectionInfoCache.keys().next().value);
  return data;
}

function placeConnectionHover(event) {
  const hover = $('#connection-hover');
  hover.style.left = `${Math.max(8, Math.min(window.innerWidth - 370, event.clientX + 16))}px`;
  hover.style.top = `${Math.max(8, Math.min(window.innerHeight - 175, event.clientY + 16))}px`;
}

async function showConnectionHover(record, event) {
  const ticket = ++hoverTicket;
  const hover = $('#connection-hover');
  hover.textContent = `${record.protocol.toUpperCase()} · ${record.state}\n${record.local} → ${record.remote}\nLinux UID ${record.uid ?? 'unknown'} · process lookup…\nPort hint and reverse DNS are not verified site identity.`;
  placeConnectionHover(event);
  hover.hidden = false;
  try {
    const info = await loadConnectionInfo(record);
    if (ticket !== hoverTicket) return;
    hover.textContent = `${record.protocol.toUpperCase()} · ${record.state}\n${record.local} → ${record.remote}\nApplication: ${info?.process_name ?? 'not visible'}${info?.pid ? ` (PID ${info.pid})` : ''}\nRemote port hint: ${info?.service_hint ?? 'unknown'}\nLinux UID ${record.uid ?? 'unknown'} · RX ${size(record.rx_queue_bytes ?? 0)} · TX ${size(record.tx_queue_bytes ?? 0)}\nWebsite name is not available from socket metadata.`;
  } catch {
    if (ticket === hoverTicket) hover.textContent += '\nProcess lookup unavailable.';
  }
}

function hideConnectionHover() { ++hoverTicket; $('#connection-hover').hidden = true; }

function openConnectionDetails(record) {
  hideConnectionHover();
  selectedConnection = record;
  selectedConnectionSeenAt = kernelSnapshot?.captured_at ?? null;
  selectedConnectionPresent = true;
  $('#detail-protocol').textContent = record.protocol;
  $('#detail-state').textContent = record.state;
  $('#detail-local').textContent = record.local;
  $('#detail-remote').textContent = record.remote;
  $('#detail-uid').textContent = record.uid ?? 'Unavailable';
  $('#detail-process').textContent = 'Looking up readable process descriptors…';
  $('#detail-service').textContent = 'Looking up…';
  $('#detail-host').textContent = 'Not looked up; optional PTR lookup below.';
  $('#detail-inode').textContent = record.inode ?? 'Unavailable';
  $('#detail-rx-queue').textContent = record.rx_queue_bytes == null ? 'Unavailable' : `${number.format(record.rx_queue_bytes)} B`;
  $('#detail-tx-queue').textContent = record.tx_queue_bytes == null ? 'Unavailable' : `${number.format(record.tx_queue_bytes)} B`;
  $('#detail-result').textContent = `Observed ${selectedConnectionSeenAt ? new Date(selectedConnectionSeenAt).toLocaleString() : 'at an unknown time'}. The remote address is a candidate only; direction is not verified.`;
  $('#connection-details').hidden = false;
  $('#drawer-backdrop').hidden = false;
  updateConnectionControls();
  $('#detail-close').focus();
  loadConnectionInfo(record).then((info) => {
    if (selectedConnection !== record) return;
    $('#detail-process').textContent = info?.process_name ? `${info.process_name} (PID ${info.pid})` : 'Not visible from this process';
    $('#detail-service').textContent = info?.service_hint ?? 'No known port label';
  }).catch(() => { if (selectedConnection === record) $('#detail-process').textContent = 'Lookup unavailable'; });
}

function renderConnections(rows) {
  const body = $('#kernel-connections');
  body.replaceChildren();
  if (!rows.length) {
    const cell = document.createElement('td'); cell.colSpan = 8; cell.className = 'empty'; cell.textContent = 'No matching sockets.';
    const row = document.createElement('tr'); row.append(cell); body.append(row);
  }
  for (const record of rows) {
    const row = document.createElement('tr'); row.className = 'connection-row';
    for (const key of ['protocol', 'local', 'remote', 'state']) {
      const cell = document.createElement('td'); cell.textContent = String(record[key]); row.append(cell);
    }
    for (const value of [record.uid ?? '—', record.rx_queue_bytes == null ? '—' : size(record.rx_queue_bytes),
      record.tx_queue_bytes == null ? '—' : size(record.tx_queue_bytes)]) {
      const cell = document.createElement('td'); cell.textContent = String(value); row.append(cell);
    }
    const action = document.createElement('td');
    const button = document.createElement('button');
    button.className = 'button secondary small connection-action'; button.textContent = 'Controls';
    button.setAttribute('aria-label', `Inspect connection ${record.local} to ${record.remote}`);
    button.addEventListener('click', () => openConnectionDetails(record));
    row.addEventListener('pointerenter', (event) => showConnectionHover(record, event));
    row.addEventListener('pointermove', placeConnectionHover);
    row.addEventListener('pointerleave', hideConnectionHover);
    button.addEventListener('focus', () => { const box = button.getBoundingClientRect(); showConnectionHover(record, { clientX: box.left, clientY: box.bottom }); });
    button.addEventListener('blur', hideConnectionHover);
    action.append(button); row.append(action); body.append(row);
  }
  selectedConnectionPresent = Boolean(selectedConnection && rows.some((row) => row.protocol === selectedConnection.protocol && row.local === selectedConnection.local && row.remote === selectedConnection.remote && row.state === selectedConnection.state));
  if (selectedConnectionPresent) {
    selectedConnectionSeenAt = kernelSnapshot?.captured_at ?? selectedConnectionSeenAt;
  }
  updateConnectionControls();
}

const number = new Intl.NumberFormat();
function size(bytes) {
  let value = Number(bytes);
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit++; }
  return `${value.toFixed(unit === 0 ? 0 : 1)} ${units[unit]}`;
}

function rate(current, prior, seconds) {
  if (!prior || seconds <= 0) return 'Collecting…';
  const delta = BigInt(current) - BigInt(prior);
  return delta < 0n ? 'Reset' : `${size(Number(delta) / seconds)}/s`;
}

const SVG_NS = 'http://www.w3.org/2000/svg';
function svgNode(tag, attributes = {}) {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [key, value] of Object.entries(attributes)) node.setAttribute(key, String(value));
  return node;
}

function drawTrend(selector, series, label, formatValue = (value) => number.format(Math.round(value)), range = []) {
  const surface = $(selector);
  surface.replaceChildren();
  surface.setAttribute('aria-label', label);
  const valid = series.flatMap((item) => item.values.filter((value) => Number.isFinite(value)));
  if (series.length === 0 || valid.length < 2) { surface.textContent = 'Collecting at least two samples…'; return; }
  const width = 620; const height = 150; const left = 60; const right = width - 10; const top = 12; const bottom = height - 23;
  const max = Math.max(1, ...valid) * 1.12;
  const point = (value, index, count) => [left + (right - left) * index / Math.max(1, count - 1), bottom - (bottom - top) * value / max];
  const svg = svgNode('svg', { viewBox: `0 0 ${width} ${height}`, preserveAspectRatio: 'none', 'aria-hidden': 'true' });
  for (const fraction of [0, .5, 1]) {
    const y = bottom - (bottom - top) * fraction;
    svg.append(svgNode('line', { x1: left, x2: right, y1: y, y2: y, class: 'chart-grid' }));
    const text = svgNode('text', { x: 0, y: y + 3, class: 'chart-label' }); text.textContent = formatValue(max * fraction); svg.append(text);
  }
  for (const item of series) {
    const segments = [];
    item.values.forEach((value, index) => {
      if (!Number.isFinite(value)) return;
      const [x, y] = point(value, index, item.values.length);
      segments.push(`${index === 0 || !Number.isFinite(item.values[index - 1]) ? 'M' : 'L'}${x.toFixed(1)} ${y.toFixed(1)}`);
    });
    svg.append(svgNode('path', { d: segments.join(' '), class: `chart-line ${item.className ?? ''}` }));
  }
  if (range.length === 2) {
    const first = svgNode('text', { x: left, y: height - 3, class: 'chart-label' }); first.textContent = new Date(range[0]).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' }); svg.append(first);
    const last = svgNode('text', { x: right, y: height - 3, class: 'chart-label', 'text-anchor': 'end' }); last.textContent = new Date(range[1]).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' }); svg.append(last);
  }
  surface.append(svg);
}

function renderHistory() {
  const history = kernelHistorySnapshot;
  if (!history) return;
  const cutoff = Date.now() - Number($('#trend-window').value) * 1_000;
  const samples = history.samples.filter((sample) => Date.parse(sample.captured_at) >= cutoff);
  const last = samples.at(-1);
  const picker = $('#trend-interface');
  const selected = picker.value;
  const names = [...new Set(last?.interfaces.map((item) => item.name) ?? [])];
  picker.replaceChildren(new Option('Auto select', ''), ...names.map((name) => new Option(name, name)));
  picker.value = names.includes(selected) ? selected : '';
  const active = picker.value || names.find((name) => name !== 'lo') || names[0];
  const sockets = samples.map((sample) => Number(sample.summary.established ?? 0));
  const range = last ? [samples[0].captured_at, last.captured_at] : [];
  drawTrend('#sessions-chart', [{ values: sockets }], `Established Linux sockets across ${samples.length} recent samples`,
    (value) => number.format(Math.round(value)), range);
  $('#trend-session-now').textContent = last ? `${number.format(sockets.at(-1))} current` : 'No samples yet';
  const rx = []; const tx = [];
  for (let i = 0; i < samples.length; i++) {
    const current = samples[i].interfaces.find((item) => item.name === active);
    const prior = samples[i - 1]?.interfaces.find((item) => item.name === active);
    const seconds = i ? (Date.parse(samples[i].captured_at) - Date.parse(samples[i - 1].captured_at)) / 1_000 : 0;
    const sampleRate = (key) => {
      if (!current || !prior || seconds <= 0) return null;
      try { const delta = BigInt(current[key]) - BigInt(prior[key]); return delta < 0n || delta > BigInt(Number.MAX_SAFE_INTEGER) ? null : Number(delta) / seconds; }
      catch { return null; }
    };
    rx.push(sampleRate('rx_bytes')); tx.push(sampleRate('tx_bytes'));
  }
  drawTrend('#traffic-chart', [{ values: rx, className: 'rx' }, { values: tx, className: 'tx' }],
    `${active ?? 'No interface'} receive and transmit byte rates across ${samples.length} recent samples`,
    (value) => `${size(value)}/s`, range);
  const latestRate = rx.at(-1);
  $('#trend-traffic-now').textContent = active ? `${active} · ${Number.isFinite(latestRate) ? `${size(latestRate)}/s RX` : 'collecting rates'}` : 'No interface';
  $('#trend-note').textContent = `${samples.length} samples · ${history.interval_seconds}s collection · current process network namespace${last?.truncated ? ' · latest socket count may be incomplete' : ''}${history.last_error ? ' · latest sample unavailable' : ''}. Rates use counter differences; graphs reset when the service restarts.`;
}

async function refreshHistory() {
  kernelHistorySnapshot = await call('/api/kernel/history', undefined, true);
  renderHistory();
}

function renderKernel() {
  if (!kernelSnapshot) return;
  const data = kernelSnapshot;
  $('#kernel-sockets').textContent = number.format(data.summary.sockets);
  $('#kernel-established').textContent = number.format(data.summary.established);
  $('#kernel-listening').textContent = number.format(data.summary.listening);
  $('#kernel-captured').textContent = new Date(data.captured_at).toLocaleTimeString();
  const states = data.summary.states ?? {};
  const protocols = data.summary.protocols ?? {};
  $('#state-established').textContent = number.format(states.ESTABLISHED ?? 0);
  $('#state-waiting').textContent = number.format(Object.entries(states).reduce((total, [state, count]) =>
    total + (['ESTABLISHED', 'LISTEN', 'UNCONN'].includes(state) ? 0 : Number(count)), 0));
  $('#state-listening').textContent = number.format(states.LISTEN ?? 0);
  $('#state-udp').textContent = number.format((protocols.udp4 ?? 0) + (protocols.udp6 ?? 0));
  $('#overview-sockets').textContent = number.format(data.summary.established);
  $('#last-refresh').textContent = `Socket snapshot ${new Date(data.captured_at).toLocaleTimeString()}`;
  const selectedInterface = $('#interface-filter').value;
  const previous = new Map(previousKernelSnapshot?.interfaces.map((item) => [item.name, item]) ?? []);
  const interval = previousKernelSnapshot ? (Date.parse(data.captured_at) - Date.parse(previousKernelSnapshot.captured_at)) / 1000 : 0;
  const interfaces = data.interfaces.filter((item) => !selectedInterface || item.name === selectedInterface).map((item) => ({
    name: item.name, rx_total: size(item.rx_bytes), rx_rate: rate(item.rx_bytes, previous.get(item.name)?.rx_bytes, interval),
    rx_packets: number.format(item.rx_packets), rx_drops: number.format(item.rx_drops),
    tx_total: size(item.tx_bytes), tx_rate: rate(item.tx_bytes, previous.get(item.name)?.tx_bytes, interval),
    tx_packets: number.format(item.tx_packets), tx_drops: number.format(item.tx_drops),
  }));
  showRows('#kernel-interfaces', interfaces, ['name', 'rx_total', 'rx_rate', 'rx_packets', 'rx_drops', 'tx_total', 'tx_rate', 'tx_packets', 'tx_drops'], 'No matching interfaces.');
  renderConnections(data.connections);
  $('#previous-connections').disabled = connectionOffset === 0;
  $('#next-connections').disabled = connectionOffset + data.connections.length >= data.summary.matched;
  $('#connection-page').textContent = `${data.summary.matched ? connectionOffset + 1 : 0}–${connectionOffset + data.connections.length} of ${data.summary.matched}`;
  $('#kernel-note').textContent = `Scope: ${data.scope}. ${data.summary.sockets} sockets observed; ${data.summary.matched} match current filters${data.truncated ? ' · snapshot truncated' : ''}. UID and receive/transmit queues come from Linux socket metadata. Queue bytes are not session throughput or XDP drop counters.`;
  $('#interface-scope').textContent = `Scope: ${data.scope}. Linux interface counters are lifetime totals and separate from HoneyMesh XDP drops. Snapshot: ${new Date(data.captured_at).toLocaleString()}.`;
}

async function refreshKernel() {
  if (kernelRefreshPending) return;
  kernelRefreshPending = true;
  const query = new URLSearchParams({ protocol: $('#protocol-filter').value, state: $('#state-filter').value,
    search: $('#connection-search').value.trim(), sort: $('#sort-connections').value,
    offset: String(connectionOffset), limit: String(CONNECTION_PAGE_SIZE) });
  try {
    const data = await call(`/api/kernel/telemetry?${query}`, undefined, true);
    previousKernelSnapshot = kernelSnapshot;
    kernelSnapshot = data;
    const picker = $('#interface-filter');
    const selected = picker.value;
    picker.replaceChildren(new Option('All interfaces', ''), ...data.interfaces.map((item) => new Option(item.name, item.name)));
    picker.value = data.interfaces.some((item) => item.name === selected) ? selected : '';
    renderKernel();
  } finally {
    kernelRefreshPending = false;
    const current = new URLSearchParams({ protocol: $('#protocol-filter').value, state: $('#state-filter').value,
      search: $('#connection-search').value.trim(), sort: $('#sort-connections').value,
      offset: String(connectionOffset), limit: String(CONNECTION_PAGE_SIZE) });
    if (sessionExpiresAt && current.toString() !== query.toString()) queueMicrotask(() => refreshKernel().catch((error) => notify(error.message, true)));
  }
}

async function refreshAgent() {
  const data = await call('/api/agent/overview', undefined, true);
  const notLinked = !data.connected && data.reason === 'not_configured';
  agentMode = data.connected ? data.mode : null;
  agentConnected = data.connected === true;
  $('#bridge-mode').textContent = data.connected ? 'Connected' : notLinked ? 'Not linked' : 'Disconnected';
  $('#overview-mode').textContent = data.connected ? data.mode : 'Unavailable';
  $('#overview-blocks').textContent = data.connected ? number.format(data.local_blocks) : '—';
  $('#overview-pending').textContent = data.connected ? number.format(data.pending_bans) : '—';
  $('#overview-primary').textContent = notLinked ? 'Agent not linked' : !data.connected ? 'Agent unavailable' : data.mode === 'TEST' ? 'Observing in TEST' : data.mode === 'ENFORCE' ? 'Enforcement active' : `Host mode: ${data.mode}`;
  $('#overview-summary').textContent = data.connected ? `Agent ${data.status}. Last checked ${new Date(data.captured_at).toLocaleTimeString()}.` : notLinked ? 'This Console has not been linked to a local HoneyMesh agent. Local observations remain available; see the Snap install manual to link an existing agent.' : `The local HoneyMesh agent could not be reached: ${data.reason}.`;
  $('#top-agent-state').textContent = data.connected ? 'Agent connected' : notLinked ? 'Agent not linked' : 'Agent offline';
  $('#top-agent-state').classList.toggle('ok', data.connected);
  $('#top-agent-state').classList.toggle('offline', !data.connected && !notLinked);
  $('#side-agent-state').textContent = data.connected ? 'Agent connected' : notLinked ? 'Agent not linked' : 'Agent unavailable';
  $('.status-dot').classList.toggle('online', data.connected);
  $('.status-dot').classList.toggle('error', !data.connected && !notLinked);
  $('#top-mode').textContent = data.connected ? data.mode : 'Unavailable';
  $('#top-mode').classList.toggle('live', data.connected && data.mode === 'ENFORCE');
  setBanner(data.connected ? `HoneyMesh ${data.mode} · agent ${data.status} · checked ${new Date(data.captured_at).toLocaleTimeString()}` : notLinked ? 'Optional HoneyMesh agent not linked. See the Snap install manual.' : `HoneyMesh agent unavailable · ${data.reason}`, !data.connected && !notLinked);
  const hostLink = $('#host-console-link');
  hostLink.hidden = !data.connected || !data.controls_available;
  if (!hostLink.hidden) hostLink.href = data.console_url;
  const banLink = $('#host-soc-link');
  banLink.hidden = hostLink.hidden;
  if (!banLink.hidden) banLink.href = data.console_url;
  const settingsLink = $('#settings-host-link');
  settingsLink.hidden = hostLink.hidden;
  if (!settingsLink.hidden) settingsLink.href = data.console_url;
  $('#settings-soc-note').textContent = data.connected
    ? 'The SOC is reachable from this service. If Chrome shows ERR_SSL_VERSION_OR_CIPHER_MISMATCH, this installed agent needs its Ed25519 leaf rotated to ECDSA. After rotation, your browser may show a private-CA warning. The SOC login is separate from this console account.'
    : notLinked ? 'No local agent is linked to this Console. See the Snap install manual in the sidebar to link an existing HoneyMesh Core agent.' : `The pinned HoneyMesh SOC is unavailable (${data.reason}). Check the agent service and certificate pin before opening host controls.`;
  updateBlockReadiness();
  $('#agent-note').textContent = data.connected
    ? `Live pinned HoneyMesh status captured ${new Date(data.captured_at).toLocaleTimeString()}. The host console requires its own operator login.`
    : notLinked ? 'No local agent is linked. Local observations remain available; see the Snap install manual to link an existing agent.' : `HoneyMesh read-only connection unavailable (${data.reason}). Host controls are unavailable.`;
}

async function refresh() {
  updateStatus(await call('/api/status'));
  await Promise.all([
    refreshKernel().catch((error) => {
      const message = error.message === '503: host_telemetry_permission_denied'
        ? 'Host telemetry is blocked. Run sudo snap connect network-decode-console:network-observe, then reload.'
        : `Host telemetry unavailable: ${error.message}`;
      $('#kernel-note').textContent = message;
      $('#interface-scope').textContent = message;
      notify(message, true);
    }),
    refreshAgent(),
    refreshHistory(),
  ]);
}

$('#account-create').addEventListener('click', run(setupAccount, 'Local administrator account created.'));
$('#account-sign-in').addEventListener('click', run(loginAccount, 'Admin signed in; saved host access restored.'));
$('#account-change-password').addEventListener('click', run(changeAccountPassword, 'Password changed; prior sessions revoked.'));
$('#sign-out').addEventListener('click', run(async () => {
  const response = await fetch('/api/session', { method: 'DELETE' });
  if (!response.ok) throw new Error('Could not sign out.');
  sessionExpiresAt = null;
  accountSignedIn = false;
  hostExpiresAt = null;
  hostActionsEnabled = false;
  hostScopedActionsEnabled = false;
  hostBanEnabled = false;
  hostGrantAvailable = false;
  hostContractStatus = 'upgrade_required';
  hostTokenSaved = false;
  agentMode = null;
  agentConnected = false;
  policy = null;
  $('#top-mode').textContent = 'Local · locked';
  $('#top-mode').classList.remove('live');
  $('#app-mode').textContent = 'Unlock';
  $('#observation-count').textContent = 'Unlock';
  $('#restriction-count').textContent = 'Unlock';
  $('#bridge-mode').textContent = 'Locked';
  $('#agent-note').textContent = 'Sign in to check the pinned HoneyMesh agent.';
  $('#host-console-link').hidden = true;
  $('#host-soc-link').hidden = true;
  $('#settings-host-link').hidden = true;
  $('#settings-soc-note').textContent = 'Sign in to check the pinned HoneyMesh SOC.';
  $('#host-result').textContent = 'Host operator session required.';
  renderHostGrants([]);
  updateHostCountdown();
  $('#kernel-sockets').textContent = 'Unlock';
  $('#kernel-established').textContent = 'Unlock';
  $('#kernel-listening').textContent = 'Unlock';
  $('#kernel-captured').textContent = 'Unlock';
  kernelSnapshot = null;
  previousKernelSnapshot = null;
  kernelHistorySnapshot = null;
  connectionOffset = 0;
  showRows('#kernel-interfaces', [], ['name', 'rx_total', 'rx_rate', 'rx_packets', 'rx_drops', 'tx_total', 'tx_rate', 'tx_packets', 'tx_drops'], 'Unlock to load kernel data.');
  selectedConnection = null;
  selectedConnectionSeenAt = null;
  selectedConnectionPresent = false;
  $('#connection-details').hidden = true;
  $('#drawer-backdrop').hidden = true;
  renderConnections([]);
  for (const id of ['sessions-chart', 'traffic-chart']) $(`#${id}`).textContent = 'Sign in to view recent samples.';
  $('#kernel-note').textContent = 'Connection results are paged in groups of 100. These counters are not XDP drop counters.';
  $('#connection-page').textContent = 'Page 1';
  $('#previous-connections').disabled = true;
  $('#next-connections').disabled = true;
  output.textContent = 'Signed out. Enter the admin password to unlock again.';
  updateCountdown();
  await loadAccountState();
}, 'Admin sessions revoked and this browser signed out.'));
$('#refresh-kernel').addEventListener('click', run(refreshKernel, 'Kernel snapshot refreshed.'));
$('#refresh-agent').addEventListener('click', run(refreshAgent, 'HoneyMesh agent status refreshed.'));
$('#host-unlock').addEventListener('click', run(unlockHost, 'HoneyMesh token verified and saved to the admin account.'));
$('#host-grants').addEventListener('click', run(hostAction(loadHostGrants), 'HoneyMesh grants loaded.'));
$('#host-counters').addEventListener('click', run(loadXdpCounters, 'HoneyMesh XDP counters loaded.'));
$('#host-interfaces').addEventListener('click', run(loadAgentInterfaces, 'HoneyMesh agent interfaces loaded.'));
$('#host-audit').addEventListener('click', run(loadActivity, 'Operator activity refreshed.'));
$('#refresh-interfaces').addEventListener('click', run(refreshKernel, 'Interface snapshot refreshed.'));
$('#host-preview').addEventListener('click', run(async () => {
  const ip = $('#host-source').value.trim(); const ttl_seconds = Number($('#host-ttl').value);
  if (!ip) throw new Error('Enter an exact IPv4 or IPv6 source address.');
  const preview = await call('/api/host/preview', { ip, ttl_seconds }, true);
  $('#host-result').textContent = JSON.stringify(preview, null, 2);
  return preview;
}, 'Read-only scope preview loaded; no host policy changed.'));
$('#host-ban').addEventListener('click', run(async () => {
  const readiness = updateBlockReadiness();
  if (!readiness.ready) { notify(readiness.message, true); if (!accountSignedIn || !hostTokenSaved) showPage('settings'); return false; }
  const ip = $('#host-source').value.trim(); const ttl_seconds = Number($('#host-ttl').value);
  if (!ip) throw new Error('Enter an exact IPv4 or IPv6 source address.');
  if (!confirm(`Apply an exact-source HoneyMesh block to ${ip} for ${$('#host-ttl').selectedOptions[0].textContent}? This affects inbound traffic from that IP across the host and expires automatically.`)) return false;
  const result = await call('/api/host/ban', { ip, ttl_seconds }, true);
  $('#host-result').textContent = JSON.stringify(result, null, 2);
  await loadHostGrants();
  return result;
}, 'Operator grant requested; inspect the kernel state.'));
$('#host-test-mode').addEventListener('click', run(hostAction(async () => {
  if (!confirm('Return HoneyMesh to TEST mode? Active enforcement will stop according to agent policy.')) return undefined;
  return call('/api/host/test-mode', { confirm: 'RETURN TO TEST' }, true);
}), 'HoneyMesh returned to TEST mode.'));
$('#detail-close').addEventListener('click', () => {
  selectedConnection = null; selectedConnectionSeenAt = null; selectedConnectionPresent = false; $('#connection-details').hidden = true; $('#drawer-backdrop').hidden = true;
});
$('#drawer-backdrop').addEventListener('click', () => $('#detail-close').click());
document.addEventListener('keydown', (event) => { if (event.key === 'Escape' && !$('#connection-details').hidden) $('#detail-close').click(); });
$('#detail-copy').addEventListener('click', run(async () => {
  if (!selectedConnectionIsCurrent()) throw new Error('Refresh the socket snapshot before using this address.');
  await navigator.clipboard.writeText(selectedConnection.remote_address);
}, 'Remote IP copied.'));
$('#detail-lookup-host').addEventListener('click', run(async () => {
  if (!selectedConnection) throw new Error('Select a connection first.');
  const record = selectedConnection;
  $('#detail-host').textContent = 'Looking up PTR record…';
  const info = await loadConnectionInfo(record, true);
  if (selectedConnection !== record) return false;
  $('#detail-host').textContent = info?.reverse_dns ? `${info.reverse_dns} (unverified PTR; not proof of website)` : 'No PTR record or lookup unavailable';
  return true;
}, 'Reverse DNS lookup completed.'));
$('#detail-use-ip').addEventListener('click', run(async () => {
  if (!selectedConnectionIsCurrent()) throw new Error('Refresh the socket snapshot before using this address.');
  $('#host-source').value = selectedConnection.remote_address;
  $('#detail-close').click();
  showPage('enforcement');
  $('#host-source').scrollIntoView({ behavior: 'smooth', block: 'center' });
  $('#host-source').focus();
}, 'Remote IP copied into the host block form; review its scope before acting.'));
$('#detail-grants').addEventListener('click', run(async () => {
  if (!selectedConnectionIsCurrent()) throw new Error('Refresh the socket snapshot before inspecting this address.');
  const decision = await call(`/api/host/decision?ip=${encodeURIComponent(selectedConnection.remote_address)}`, undefined, true);
  const outcome = {
    kernel_block_confirmed: 'Agent reports this kernel block applied',
    override_active: 'Temporary release override is active',
    grant_pending_or_not_applied: 'Grant exists; kernel block is not confirmed',
    no_active_grant: 'No active UEE grant for this address',
  }[decision.outcome] ?? 'Agent outcome unavailable';
  const owners = decision.grants.map((grant) =>
    `${grant.owner_kind ?? 'unknown'} / ${grant.owner_id ?? 'unknown'}: ${grant.reason ?? 'no reason'} · policy ${grant.policy_version ?? 'unknown'} · expires ${grant.expires_at ? new Date(grant.expires_at).toLocaleString() : 'unknown'}`);
  const drops = decision.global_xdp_drop_totals;
  $('#detail-result').textContent = [
    `${outcome} · ${new Date(decision.captured_at).toLocaleString()}`,
    `Host mode: ${decision.host_mode ?? 'unavailable'} · XDP attached: ${decision.xdp_attached === null ? 'unavailable' : decision.xdp_attached ? 'yes' : 'no'}`,
    decision.override_expires_at ? `Override expires: ${new Date(decision.override_expires_at).toLocaleString()}` : null,
    decision.last_reconciliation_error ? `Reconciliation error: ${decision.last_reconciliation_error}` : null,
    ...owners,
    drops ? `Global XDP exact-ban drops: IPv4 ${drops.ipv4?.packets ?? '—'} packets; IPv6 ${drops.ipv6?.packets ?? '—'} packets. These are not per-address counts.` : 'Global XDP drop counters unavailable.',
    decision.proposed_scope, decision.observation_limit,
  ].filter(Boolean).join('\n');
}, 'Current agent decision explained for this IP.'));
$('#detail-history').addEventListener('click', run(async () => {
  if (!selectedConnectionIsCurrent()) throw new Error('Refresh the socket snapshot before inspecting this address.');
  const history = await call(`/api/host/history?ip=${encodeURIComponent(selectedConnection.remote_address)}`, undefined, true);
  const events = history.events ?? [];
  $('#detail-result').textContent = events.length ? events.map((event) =>
    `${new Date(event.at).toLocaleString()} · ${event.operation} · ${event.result} · ${event.reconcile_status}\nOwners: ${(event.owner_ids ?? []).join(', ') || 'none'}\nPolicies: ${(event.policy_versions ?? []).join(', ') || 'none'}${event.kernel_error ? `\nKernel error: ${event.kernel_error}` : ''}`).join('\n\n')
    : 'No UEE reconciliation history for this address. This is not a packet trace.';
}, 'Bounded UEE reconciliation history loaded.'));
$('#detail-block').addEventListener('click', run(async () => {
  if (!selectedConnectionIsCurrent()) throw new Error('Refresh the socket snapshot before requesting a block.');
  await restoreHostSession();
  const readiness = updateBlockReadiness();
  if (!readiness.ready) { $('#detail-result').textContent = readiness.message; notify(readiness.message, true); return false; }
  const ip = selectedConnection.remote_address;
  const ttl_seconds = Number($('#detail-ttl').value);
  const grants = await call('/api/host/grants', undefined, true);
  const existing = grants.find((item) => normalizedAddress(item.State?.IP ?? item.state?.IP ?? item.state?.ip ?? '') === normalizedAddress(ip));
  const owners = existing?.Grants?.length ?? existing?.grants?.length ?? 0;
  if (!confirm(`Request a host-wide ingress block for ${ip} for ${$('#detail-ttl').selectedOptions[0].textContent}? This socket snapshot does not verify direction or hostile behavior. ${owners} existing grant owner(s) will remain independent. The block expires automatically.`)) return false;
  const result = await call('/api/host/ban', { ip, ttl_seconds }, true);
  $('#detail-result').textContent = `Block request accepted for ${ip}. Review Enforcement to confirm the effective kernel state.`;
  $('#host-result').textContent = JSON.stringify(result, null, 2);
  await loadHostGrants();
}, 'Source-block request sent; inspect reconciliation before treating it as applied.'));
$('#interface-filter').addEventListener('change', renderKernel);
for (const id of ['protocol-filter', 'state-filter', 'sort-connections']) $(`#${id}`).addEventListener('change', () => {
  connectionOffset = 0; refreshKernel().catch((error) => notify(error.message, true));
});
let searchTimer;
$('#connection-search').addEventListener('input', () => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => { connectionOffset = 0; refreshKernel().catch((error) => notify(error.message, true)); }, 250);
});
$('#previous-connections').addEventListener('click', () => { connectionOffset = Math.max(0, connectionOffset - CONNECTION_PAGE_SIZE); refreshKernel().catch((error) => notify(error.message, true)); });
$('#next-connections').addEventListener('click', () => { connectionOffset += CONNECTION_PAGE_SIZE; refreshKernel().catch((error) => notify(error.message, true)); });
setInterval(() => {
  if (!sessionExpiresAt || !$('#auto-refresh').checked || document.hidden || Date.now() >= sessionExpiresAt) return;
  refreshKernel().catch((error) => { $('#kernel-note').textContent = `Refresh failed: ${error.message}`; });
  refreshHistory().catch((error) => { $('#trend-note').textContent = `Trend refresh failed: ${error.message}`; });
  refreshAgent().catch((error) => { $('#agent-note').textContent = `Agent refresh failed: ${error.message}`; });
}, 5_000);
for (const id of ['trend-window', 'trend-interface']) $(`#${id}`).addEventListener('change', renderHistory);
$('#attempt').addEventListener('click', run(async () => {
  await call('/api/lab/attempt', { source_ip: $('#source').value.trim() });
  await refresh();
}, 'Synthetic login observation recorded.'));
$('#probe').addEventListener('click', run(() =>
  call('/api/lab/probe', { source_ip: $('#source').value.trim() }),
  'Application restriction checked.'));
$('#release').addEventListener('click', run(async () => {
  await call('/api/lab/release', { source_ip: $('#source').value.trim() });
  await refresh();
}, 'Application restriction released.'));
$('#review').addEventListener('click', run(async () => {
  if (!policy) await refresh();
  await call('/api/review', { proposed_policy: { ...policy, mode: 'ENFORCE' } });
}, 'Policy comparison ready in Operation result.'));
$('#replay').addEventListener('click', run(async () => {
  if (!policy) await refresh();
  await call('/api/replay', { proposed_policy: { ...policy, mode: 'ENFORCE' } });
}, 'Security Replay ready in Operation result.'));

for (const button of document.querySelectorAll('[data-nav]')) button.addEventListener('click', () => showPage(button.dataset.nav));
for (const button of document.querySelectorAll('[data-goto]')) button.addEventListener('click', () => showPage(button.dataset.goto));
$('#top-account').addEventListener('click', () => showPage('settings'));
$('#mobile-menu-toggle').addEventListener('click', () => {
  const open = $('.sidebar').classList.toggle('open');
  $('#mobile-menu-toggle').setAttribute('aria-expanded', String(open));
});
$('#close-menu').addEventListener('click', () => {
  $('.sidebar').classList.remove('open');
  $('#mobile-menu-toggle').setAttribute('aria-expanded', 'false');
  $('#mobile-menu-toggle').focus();
});
showPage('settings', false);

async function initialize() {
  try {
    const response = await fetch('/health');
    if (!response.ok) throw new Error('health unavailable');
    const health = await response.json();
    $('#host-name').textContent = health.host || 'Local host';
  } catch {
    $('#top-mode').textContent = 'Offline';
    setBanner('Local Console service is unavailable. Check snap services network-decode-console and reload.', true);
    notify('Cannot reach the local Console service. Check snap services network-decode-console.', true);
    return;
  }
  try { await loadAccountState(); }
  catch (error) {
    setBanner('Console data could not load. Check the local Console service and reload.', true);
    notify(`Console data could not load: ${error.message}`, true);
  }
}
void initialize();
setInterval(() => {
  if (!accountSignedIn || document.hidden) return;
  fetch('/api/account/session').then(async (response) => {
    if (!response.ok) { accountSignedIn = false; sessionExpiresAt = null; await loadAccountState(); return; }
    sessionExpiresAt = Date.parse((await response.json()).expires_at);
    hostExpiresAt = sessionExpiresAt;
  }).catch(() => {});
}, 60 * 60 * 1_000);

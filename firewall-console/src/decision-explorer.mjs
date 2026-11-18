import { isIP } from 'node:net';

export function canonicalAddress(value) {
  if (typeof value !== 'string' || value.length > 45 || !isIP(value)) return null;
  if (isIP(value) === 4) return value;
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(value);
  if (mapped && isIP(mapped[1]) === 4) return mapped[1];
  try { return new URL(`http://[${value}]/`).hostname.slice(1, -1); }
  catch { return null; }
}

const field = (item, name, alias) => item?.[name] ?? item?.[alias];

export function explainHostDecision(ip, snapshot, contract = null, counters = null, capturedAt = new Date().toISOString()) {
  const address = canonicalAddress(ip);
  if (!address || !Array.isArray(snapshot)) throw new TypeError('invalid_decision_input');
  const match = snapshot.find((item) => canonicalAddress(field(field(item, 'State', 'state'), 'IP', 'ip')) === address);
  const state = field(match, 'State', 'state') ?? {};
  const grants = (field(match, 'Grants', 'grants') ?? []).map((grant) => {
    const owner = field(grant, 'Owner', 'owner') ?? {};
    return {
      owner_kind: field(owner, 'Kind', 'kind') ?? null,
      owner_id: field(owner, 'ID', 'id') ?? null,
      reason: field(grant, 'Reason', 'reason') ?? null,
      policy_version: field(grant, 'PolicyVersion', 'policy_version') ?? null,
      expires_at: field(grant, 'ExpiresAt', 'expires_at') ?? null,
    };
  });
  const kernelApplied = field(state, 'KernelApplied', 'kernel_applied') === true;
  const overrideExpiry = field(state, 'OverrideExpiresAt', 'override_expires_at');
  const overrideActive = Boolean(overrideExpiry && Date.parse(overrideExpiry) > Date.parse(capturedAt));
  const outcome = kernelApplied ? 'kernel_block_confirmed'
    : overrideActive ? 'override_active'
      : grants.length ? 'grant_pending_or_not_applied' : 'no_active_grant';
  return {
    ip: address, captured_at: capturedAt, outcome, kernel_applied: kernelApplied,
    host_mode: contract?.mode ?? null, xdp_attached: contract?.xdp_attached ?? null,
    override_expires_at: overrideActive ? overrideExpiry : null,
    last_reconciliation_error: field(state, 'LastError', 'last_error') || null,
    grants,
    global_xdp_drop_totals: counters ?? null,
    global_counters_are_per_source: false,
    proposed_scope: 'An exact-source block would affect inbound traffic from this IP across the host, not just the selected socket.',
    observation_limit: 'This snapshot does not establish connection direction, hostile intent, packet history, or whether other firewall paths accepted traffic.',
  };
}

import { isIP } from 'node:net';
import { readdir, readFile, readlink } from 'node:fs/promises';
import { reverse } from 'node:dns/promises';

const MAX_PIDS = 512;
const MAX_FDS_PER_PID = 512;
const LOOKUP_MS = 600;
const PORT_LABELS = new Map([[22, 'SSH'], [53, 'DNS'], [80, 'HTTP'], [123, 'NTP'], [443, 'HTTPS'], [587, 'SMTP submission'], [5432, 'PostgreSQL'], [6379, 'Redis']]);

export function serviceHint(port) {
  return PORT_LABELS.get(Number(port)) ?? null;
}

export async function findSocketProcess(inode, { procRoot = '/proc', deadlineMs = LOOKUP_MS } = {}) {
  if (!/^\d{1,20}$/.test(String(inode ?? ''))) throw new RangeError('invalid_socket_inode');
  const deadline = Date.now() + deadlineMs;
  let pids;
  try { pids = (await readdir(procRoot)).filter((name) => /^\d+$/.test(name)).slice(0, MAX_PIDS); }
  catch { return { process_name: null, pid: null, reason: 'proc_unavailable' }; }
  const target = `socket:[${inode}]`;
  for (const pid of pids) {
    if (Date.now() >= deadline) return { process_name: null, pid: null, reason: 'lookup_timed_out' };
    let fds;
    try { fds = (await readdir(`${procRoot}/${pid}/fd`)).slice(0, MAX_FDS_PER_PID); }
    catch { continue; }
    for (const fd of fds) {
      if (Date.now() >= deadline) return { process_name: null, pid: null, reason: 'lookup_timed_out' };
      try {
        if (await readlink(`${procRoot}/${pid}/fd/${fd}`) !== target) continue;
        const name = (await readFile(`${procRoot}/${pid}/comm`, 'utf8')).trim().slice(0, 64);
        return { process_name: name || null, pid: Number(pid), reason: 'proc_socket_inode_match' };
      } catch { /* A process or descriptor may disappear during the scan. */ }
    }
  }
  return { process_name: null, pid: null, reason: 'not_visible_or_not_found' };
}

export async function inspectConnection({ inode, remote_address, remote_port, resolveHost = false }, options = {}) {
  if (!/^\d{1,20}$/.test(String(inode ?? '')) || !isIP(remote_address) ||
      !Number.isInteger(Number(remote_port)) || Number(remote_port) < 0 || Number(remote_port) > 65535) {
    throw new RangeError('invalid_connection');
  }
  const owner = await findSocketProcess(inode, options);
  let reverseDns = null;
  if (resolveHost) {
    try {
      const names = await Promise.race([reverse(remote_address), new Promise((_, reject) => setTimeout(() => reject(new Error('lookup_timeout')), 1500))]);
      reverseDns = Array.isArray(names) ? names[0]?.slice(0, 255) ?? null : null;
    } catch { /* Reverse DNS is optional and never proves the site visited. */ }
  }
  return { ...owner, service_hint: serviceHint(remote_port), reverse_dns: reverseDns,
    reverse_dns_is_site_identity: false, scope: 'current_process_namespace_snapshot' };
}

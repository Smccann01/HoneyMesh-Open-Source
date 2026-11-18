import { open } from 'node:fs/promises';

const MAX_BYTES = 1_048_576;
const MAX_CONNECTIONS = 200;
const TCP_STATES = { '01': 'ESTABLISHED', '02': 'SYN_SENT', '03': 'SYN_RECV', '04': 'FIN_WAIT_1', '05': 'FIN_WAIT_2', '06': 'TIME_WAIT', '07': 'CLOSE', '08': 'CLOSE_WAIT', '09': 'LAST_ACK', '0A': 'LISTEN', '0B': 'CLOSING' };

async function readBounded(path) {
  const file = await open(path, 'r');
  try {
    const buffer = Buffer.alloc(MAX_BYTES + 1);
    const { bytesRead } = await file.read(buffer, 0, buffer.length, 0);
    return { text: buffer.subarray(0, Math.min(bytesRead, MAX_BYTES)).toString('utf8'), truncated: bytesRead > MAX_BYTES };
  } finally { await file.close(); }
}

export function decodeAddress(value, family) {
  const [raw, portHex] = value.split(':');
  const size = family === 4 ? 8 : 32;
  if (!raw || raw.length !== size || !/^[0-9A-Fa-f]+$/.test(raw) || !/^[0-9A-Fa-f]{4}$/.test(portHex ?? '')) return null;
  const bytes = raw.match(/../g);
  const ordered = [];
  for (let i = 0; i < bytes.length; i += 4) ordered.push(...bytes.slice(i, i + 4).reverse().map((part) => part.toLowerCase()));
  const address = family === 4
    ? ordered.map((part) => parseInt(part, 16)).join('.')
    : ordered.slice(0, 10).every((part) => part === '00') && ordered[10] === 'ff' && ordered[11] === 'ff'
      ? `::ffff:${ordered.slice(12).map((part) => parseInt(part, 16)).join('.')}`
      : new URL(`http://[${Array.from({ length: 8 }, (_, i) => ordered.slice(i * 2, i * 2 + 2).join('').toLowerCase()).join(':')}]/`).hostname.slice(1, -1);
  return { address, port: parseInt(portHex, 16) };
}

export function parseSocketTable(content, protocol, family) {
  const rows = [];
  for (const line of content.split('\n').slice(1)) {
    const fields = line.trim().split(/\s+/);
    if (fields.length < 4) continue;
    const local = decodeAddress(fields[1], family);
    const remote = decodeAddress(fields[2], family);
    if (!local || !remote) continue;
    const queues = /^([0-9A-Fa-f]+):([0-9A-Fa-f]+)$/.exec(fields[4] ?? '');
    const uid = /^\d+$/.test(fields[7] ?? '') ? Number(fields[7]) : null;
    const inode = /^\d+$/.test(fields[9] ?? '') ? fields[9] : null;
    rows.push({ protocol: `${protocol}${family}`, local: `${family === 6 ? `[${local.address}]` : local.address}:${local.port}`,
      remote: `${family === 6 ? `[${remote.address}]` : remote.address}:${remote.port}`,
      local_address: local.address, local_port: local.port, remote_address: remote.address, remote_port: remote.port,
      state: protocol === 'tcp' ? TCP_STATES[fields[3].toUpperCase()] ?? 'UNKNOWN' : 'UNCONN',
      tx_queue_bytes: queues ? parseInt(queues[1], 16) : null,
      rx_queue_bytes: queues ? parseInt(queues[2], 16) : null,
      uid: Number.isSafeInteger(uid) ? uid : null,
      inode });
  }
  return rows;
}

export function parseInterfaces(content) {
  const interfaces = [];
  for (const line of content.split('\n').slice(2)) {
    const colon = line.indexOf(':');
    if (colon < 0) continue;
    const name = line.slice(0, colon).trim();
    const fields = line.slice(colon + 1).trim().split(/\s+/);
    if (!name || fields.length < 16 || fields.some((field) => !/^\d+$/.test(field))) continue;
    interfaces.push({ name, rx_bytes: fields[0], rx_packets: fields[1], rx_drops: fields[3], tx_bytes: fields[8], tx_packets: fields[9], tx_drops: fields[11] });
    if (interfaces.length === 64) break;
  }
  return interfaces;
}

export function selectConnections(all, { protocol = '', state = '', search = '', sort = 'state', offset = 0, limit = 100 } = {}) {
  if (!['', 'tcp4', 'tcp6', 'udp4', 'udp6'].includes(protocol) ||
      !['', 'ESTABLISHED', 'LISTEN', 'UNCONN', 'OTHER'].includes(state) ||
      !['state', 'local', 'remote', 'protocol'].includes(sort) ||
      typeof search !== 'string' || search.length > 64 ||
      !Number.isInteger(offset) || offset < 0 || offset > 100_000 ||
      !Number.isInteger(limit) || limit < 1 || limit > MAX_CONNECTIONS) throw new RangeError('invalid_connection_filter');
  const term = search.toLowerCase();
  const matching = all.filter((row) => (!protocol || row.protocol === protocol) &&
    (!state || (state === 'OTHER' ? !['ESTABLISHED', 'LISTEN', 'UNCONN'].includes(row.state) : row.state === state)) &&
    (!term || `${row.local} ${row.remote}`.toLowerCase().includes(term)));
  matching.sort((a, b) => a[sort].localeCompare(b[sort]) || a.local.localeCompare(b.local));
  return { connections: matching.slice(offset, offset + limit), matched: matching.length, offset, limit };
}

export async function collectKernelTelemetry(filters = {}) {
  const tables = [ ['tcp', 4], ['tcp6', 6], ['udp', 4], ['udp6', 6] ];
  const results = await Promise.all(tables.map(async ([name, family]) => {
    try { const data = await readBounded(`/proc/net/${name}`); return { ...data, protocol: name.startsWith('tcp') ? 'tcp' : 'udp', family }; }
    catch (error) { if (error.code === 'ENOENT') return null; throw error; }
  }));
  const network = await readBounded('/proc/net/dev');
  const all = results.flatMap((data) => data ? parseSocketTable(data.text, data.protocol, data.family) : []);
  const selected = selectConnections(all, filters);
  const protocols = { tcp4: 0, tcp6: 0, udp4: 0, udp6: 0 };
  const states = {};
  for (const row of all) { protocols[row.protocol]++; states[row.state] = (states[row.state] ?? 0) + 1; }
  return {
    captured_at: new Date().toISOString(),
    scope: 'current_process_network_namespace',
    source: 'Linux /proc/net socket and interface counters',
    summary: { sockets: all.length, established: states.ESTABLISHED ?? 0, listening: states.LISTEN ?? 0,
      matched: selected.matched, protocols, states },
    connections: selected.connections,
    page: { offset: selected.offset, limit: selected.limit },
    interfaces: parseInterfaces(network.text),
    truncated: network.truncated || results.some((data) => data?.truncated),
  };
}

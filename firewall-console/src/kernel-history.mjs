const DEFAULT_INTERVAL_MS = 5_000;
const DEFAULT_MAX_SAMPLES = 120;

export function createKernelHistory(collect, { intervalMs = DEFAULT_INTERVAL_MS, maxSamples = DEFAULT_MAX_SAMPLES } = {}) {
  if (typeof collect !== 'function' || !Number.isInteger(intervalMs) || intervalMs < 100 ||
      !Number.isInteger(maxSamples) || maxSamples < 2 || maxSamples > 720) throw new TypeError('invalid_kernel_history_config');
  const samples = [];
  let timer = null;
  let pending = null;
  let lastError = null;

  async function sample() {
    if (pending) return pending;
    pending = (async () => {
      try {
        const data = await collect({ offset: 0, limit: 1 });
        if (!data?.summary || !Array.isArray(data.interfaces)) throw new Error('invalid_sample');
        samples.push({ captured_at: data.captured_at ?? new Date().toISOString(), truncated: Boolean(data.truncated),
          summary: { sockets: data.summary.sockets ?? 0, established: data.summary.established ?? 0,
            listening: data.summary.listening ?? 0, protocols: data.summary.protocols ?? {}, states: data.summary.states ?? {} },
          interfaces: data.interfaces.map(({ name, rx_bytes, tx_bytes, rx_packets, tx_packets, rx_drops, tx_drops }) =>
            ({ name, rx_bytes, tx_bytes, rx_packets, tx_packets, rx_drops, tx_drops })) });
        if (samples.length > maxSamples) samples.splice(0, samples.length - maxSamples);
        lastError = null;
      } catch { lastError = 'sample_unavailable'; }
    })();
    try { await pending; } finally { pending = null; }
  }

  return {
    sample,
    start() {
      if (timer) return;
      void sample();
      timer = setInterval(() => { void sample(); }, intervalMs);
      timer.unref?.();
    },
    stop() { if (timer) clearInterval(timer); timer = null; },
    snapshot() { return { scope: 'current_process_network_namespace', interval_seconds: intervalMs / 1_000,
      retained_samples: samples.length, last_error: lastError, samples: samples.slice() }; },
  };
}

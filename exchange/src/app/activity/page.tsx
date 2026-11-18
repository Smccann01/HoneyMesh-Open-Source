"use client";

import { useEffect, useRef, useState } from "react";
import Link from "next/link";

import "./activity.css";

type ActivityRecord = { sourceId: string; sourceIp: string | null; reason: string; layer: "Application" | "HoneyMesh agent"; protocol: "HTTPS" | "Unknown"; expiresAt: string };
type HistoryRecord = {
  id: string; sourceId: string; sourceIp: string | null; behavior: string; reasonCode: string;
  protocol: "HTTPS" | "Unknown"; serviceClass: string; detector: string;
  layer: "Application"; outcome: "Observed" | "Limit armed" | "Blocked" | "Expired";
  observedAt: string; expiresAt: string | null; enforcedAt: string | null; hitCount: number;
};
type HistoryData = {
  enabled: boolean; days: number; records: HistoryRecord[]; nextCursor: string | null;
  oldestAvailableAt: string | null; historyTruncated: boolean;
  daily: Array<{ day: string; observed: number; controlled: number }>;
};
type ActivityData = {
  enabled: boolean;
  updatedAt: string;
  guardMode?: "off" | "observe" | "enforce";
  agentStatus?: "not_configured" | "connected" | "unavailable";
  agentMode?: "TEST" | "ENFORCE" | "LOCKDOWN" | "unknown" | null;
  recentFailureCount?: number;
  activeSources?: number;
  activeControls?: number;
  records?: ActivityRecord[];
};

function remaining(expiresAt: string, now: number) {
  const seconds = Math.max(0, Math.ceil((Date.parse(expiresAt) - now) / 1000));
  return `${Math.floor(seconds / 60)}m ${String(seconds % 60).padStart(2, "0")}s`;
}

export default function ActivityPage() {
  const [data, setData] = useState<ActivityData | null>(null);
  const [error, setError] = useState(false);
  const [now, setNow] = useState(() => Date.now());
  const [history, setHistory] = useState<HistoryData | null>(null);
  const [historyError, setHistoryError] = useState(false);
  const [days, setDays] = useState(30);
  const [reason, setReason] = useState("");
  const [protocol, setProtocol] = useState("");
  const [outcome, setOutcome] = useState("");
  const [loadingMore, setLoadingMore] = useState(false);
  const loadedMoreRef = useRef(false);

  useEffect(() => {
    let mounted = true;
    async function refresh() {
      try {
        const response = await fetch("/api/public/exchange-activity", { cache: "no-store" });
        if (!response.ok) throw new Error("Activity request failed");
        const next = await response.json() as ActivityData;
        if (mounted) { setData(next); setError(false); }
      } catch {
        if (mounted) setError(true);
      }
    }
    void refresh();
    const refreshTimer = window.setInterval(() => { void refresh(); }, 15_000);
    const clockTimer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => { mounted = false; window.clearInterval(refreshTimer); window.clearInterval(clockTimer); };
  }, []);

  useEffect(() => {
    let mounted = true;
    loadedMoreRef.current = false;
    const query = new URLSearchParams({ days: String(days) });
    if (reason) query.set("reason", reason);
    if (protocol) query.set("protocol", protocol);
    if (outcome) query.set("outcome", outcome);
    async function refresh() {
      if (loadedMoreRef.current) return;
      try {
        const response = await fetch(`/api/public/exchange-history?${query}`, { cache: "no-store" });
        if (!response.ok) throw new Error("History request failed");
        const next = await response.json() as HistoryData;
        if (mounted) { setHistory(next); setHistoryError(false); }
      } catch { if (mounted) setHistoryError(true); }
    }
    void refresh();
    const timer = window.setInterval(() => { void refresh(); }, 30_000);
    return () => { mounted = false; window.clearInterval(timer); };
  }, [days, reason, protocol, outcome]);

  async function loadMore() {
    if (!history?.nextCursor || loadingMore) return;
    loadedMoreRef.current = true;
    setLoadingMore(true);
    const query = new URLSearchParams({ days: String(days), cursor: history.nextCursor });
    if (reason) query.set("reason", reason);
    if (protocol) query.set("protocol", protocol);
    if (outcome) query.set("outcome", outcome);
    try {
      const response = await fetch(`/api/public/exchange-history?${query}`, { cache: "no-store" });
      if (!response.ok) throw new Error("History request failed");
      const next = await response.json() as HistoryData;
      setHistory((previous) => previous ? { ...next, records: [...previous.records, ...next.records] } : next);
      setHistoryError(false);
    } catch { setHistoryError(true); }
    finally { setLoadingMore(false); }
  }

  const active = (data?.records ?? []).filter((record) => Date.parse(record.expiresAt) > now);
  const available = data?.enabled === true && !error;
  const guardLabel = data?.guardMode === "enforce" ? "Application controls active" : data?.guardMode === "observe" ? "Application observation" : "Application Guard off";
  const agentLabel = data?.agentStatus === "connected" ? data.agentMode === "TEST" ? "Agent connected · Test mode, no packet blocks" : "Agent reporting" : data?.agentStatus === "unavailable" ? "Agent unavailable" : "Agent not connected";
  const controlledTotal = history?.daily.reduce((sum, bucket) => sum + bucket.controlled, 0) ?? 0;
  const dailyMap = new Map(history?.daily.map((bucket) => [bucket.day, bucket]) ?? []);
  const chartDays = Array.from({ length: days }, (_, index) => {
    const date = new Date(now);
    date.setUTCHours(0, 0, 0, 0);
    date.setUTCDate(date.getUTCDate() - (days - 1 - index));
    const day = date.toISOString().slice(0, 10);
    return dailyMap.get(day) ?? { day, observed: 0, controlled: 0 };
  });
  const chartMax = Math.max(1, ...chartDays.map((bucket) => bucket.observed + bucket.controlled));

  return (
    <main className="activity-page">
      <div className="activity-orbit activity-orbit-one" aria-hidden="true" />
      <div className="activity-orbit activity-orbit-two" aria-hidden="true" />
      <div className="activity-wrap">
        <header className="activity-header">
          <Link className="activity-brand" href="/" aria-label="HoneyMesh Exchange home">
            <span className="activity-brand-mark" aria-hidden="true" />
            <span><strong>HONEY MESH</strong><small>EXCHANGE DEFENSE</small></span>
          </Link>
          <Link className="activity-home-link" href="/downloads">Download HoneyMesh <span aria-hidden="true">↗</span></Link>
        </header>

        <section className="activity-hero">
          <div className="activity-eyebrow"><span className="activity-live-dot" /> LIVE DEFENSE VIEW</div>
          <h1>The Exchange protects<br /><em>its own front door.</em></h1>
          <p>Watch this Exchange service&apos;s own application controls and recorded history. Confirmed controls show the source IP and the layer actually applied. This view does not demonstrate distributed enforcement on customer nodes.</p>
          <div className="activity-state-line">
            <span className={available ? "activity-state-good" : "activity-state-muted"}>{error ? "Activity feed unavailable" : !data ? "Connecting to activity feed" : data.enabled ? guardLabel : "Activity view not enabled"}</span>
            <span className="activity-state-divider" />
            <span>{available ? agentLabel : "No live agent status"}</span>
          </div>
        </section>

        <section className="activity-metrics" aria-label="Current Exchange activity">
          <div className="activity-metric"><span className="activity-metric-icon">◎</span><strong>{available ? data.activeSources ?? 0 : "—"}</strong><span>Sources with active controls</span><small>Unique source addresses</small></div>
          <div className="activity-metric"><span className="activity-metric-icon">⬡</span><strong>{available ? active.length : "—"}</strong><span>Active controls shown</span><small>Application and agent</small></div>
          <div className="activity-metric"><span className="activity-metric-icon">◷</span><strong>{history && !historyError ? controlledTotal : "—"}</strong><span>Controls in selected period</span><small>Application Guard · {days} {days === 1 ? "day" : "days"}</small></div>
        </section>

        <section className="activity-panel">
          <div className="activity-panel-heading"><div><p className="activity-kicker">CURRENT CONTROLS</p><h2>Active local Exchange controls</h2></div><span className="activity-refresh">Refreshes every 15 seconds</span></div>
          {available && active.length ? (
            <div className="activity-table-wrap"><table><thead><tr><th>Source IP</th><th>Detected behavior</th><th>Observed protocol</th><th>Control layer</th><th>Expires in</th></tr></thead><tbody>{active.map((record, index) => <tr key={`${record.sourceId}-${record.layer}-${index}`}><td className="activity-source">{record.sourceIp ?? "Pending confirmation"}</td><td>{record.reason}</td><td>{record.protocol}</td><td><span className={record.layer === "HoneyMesh agent" ? "activity-layer agent" : "activity-layer"}>{record.layer}</span></td><td className="activity-expiry">{remaining(record.expiresAt, now)}</td></tr>)}</tbody></table></div>
          ) : (
            <div className="activity-empty"><span aria-hidden="true">◇</span><h3>{error ? "Activity is temporarily unavailable" : !data ? "Connecting to the Exchange" : !data.enabled ? "Public activity is not enabled yet" : "No active Exchange controls"}</h3><p>{error ? "The live feed could not be reached. Try again shortly." : !data?.enabled ? "This view will become live when the Exchange operator enables it." : "A quiet table is a good thing. New controls appear here when the Exchange detects repeated abuse."}</p></div>
          )}
          <div className="activity-panel-footer"><span>Confirmed source IPs are public here. Payloads and credentials are not shown.</span><span>{available ? `Updated ${new Date(data.updatedAt).toLocaleTimeString()}` : "Awaiting live data"}</span></div>
        </section>

        <section className="activity-panel activity-history" aria-labelledby="history-heading">
          <div className="activity-panel-heading"><div><p className="activity-kicker">VERIFIED HISTORY</p><h2 id="history-heading">Exchange event timeline</h2></div><span className="activity-refresh">Up to 30 days · newest first</span></div>
          <div className="activity-history-intro"><p>Observed behavior and temporary limits are separate outcomes. “HTTPS” means the request reached the Exchange through its trusted web proxy; it does not describe the scope of a later IP ban.</p><span>{history?.oldestAvailableAt ? `Oldest available: ${new Date(history.oldestAvailableAt).toLocaleDateString()}` : "No retained records yet"}{history?.historyTruncated ? " · Volume cap shortened the window" : ""}</span></div>
          <div className="activity-filters" aria-label="Filter activity history">
            <label>Period<select value={days} onChange={(event) => { setHistory(null); setDays(Number(event.target.value)); }}><option value={1}>24 hours</option><option value={7}>7 days</option><option value={30}>30 days</option></select></label>
            <label>Behavior<select value={reason} onChange={(event) => { setHistory(null); setReason(event.target.value); }}><option value="">All behaviors</option><option value="invalid_signature_burst">Invalid signatures</option><option value="replay_burst">Replay attempts</option><option value="anonymous_rate_burst">Unauthenticated rate</option></select></label>
            <label>Protocol<select value={protocol} onChange={(event) => { setHistory(null); setProtocol(event.target.value); }}><option value="">All protocols</option><option value="HTTPS">HTTPS</option><option value="Unknown">Unknown</option></select></label>
            <label>Outcome<select value={outcome} onChange={(event) => { setHistory(null); setOutcome(event.target.value); }}><option value="">All outcomes</option><option value="observed">Observed</option><option value="controlled">Controlled</option></select></label>
          </div>
          <div className="activity-chart" role="img" aria-label={`Daily observed events and controls over ${days} days`}>
            {chartDays.map((bucket) => <div key={bucket.day} className="activity-chart-day" title={`${bucket.day}: ${bucket.observed} observed, ${bucket.controlled} controls`}><span className="activity-chart-bar observed" style={{ height: bucket.observed ? `${Math.max(2, bucket.observed / chartMax * 100)}%` : 0 }} /><span className="activity-chart-bar controlled" style={{ height: bucket.controlled ? `${Math.max(2, bucket.controlled / chartMax * 100)}%` : 0 }} /></div>)}
          </div>
          <div className="activity-chart-legend"><span><i className="observed" /> Observed</span><span><i className="controlled" /> Temporary controls</span><small>Each bar is one UTC day</small></div>
          {historyError ? <div className="activity-history-empty">History is temporarily unavailable. Active controls above continue to refresh.</div> : !history ? <div className="activity-history-empty">Loading verified activity…</div> : history.records.length ? (
            <div className="activity-table-wrap"><table><thead><tr><th>Observed</th><th>Source IP</th><th>Behavior</th><th>Protocol</th><th>Outcome</th><th>Control window</th></tr></thead><tbody>{history.records.map((record) => <tr key={record.id}><td>{new Date(record.observedAt).toLocaleString()}</td><td className="activity-source">{record.sourceIp ?? "Not recorded"}{!record.sourceIp ? <small className="activity-cell-note">{record.sourceId}</small> : null}</td><td>{record.behavior}<small className="activity-cell-note">{record.serviceClass} · {record.hitCount > 0 ? `${record.hitCount} observations` : "legacy record"}</small></td><td>{record.protocol}</td><td><span className={`activity-outcome ${record.outcome.toLowerCase().replaceAll(" ", "-")}`}>{record.outcome}</span></td><td>{record.expiresAt ? <>{new Date(record.observedAt).toLocaleTimeString()}–{new Date(record.expiresAt).toLocaleTimeString()}<small className="activity-cell-note">{record.enforcedAt ? "429 response confirmed" : "No 429 confirmation stored"}</small></> : "No control applied"}</td></tr>)}</tbody></table></div>
          ) : <div className="activity-history-empty">No verified events match these filters.</div>}
          {history?.nextCursor && !historyError ? <div className="activity-history-more"><button type="button" onClick={() => void loadMore()} disabled={loadingMore}>{loadingMore ? "Loading…" : "Load older events"}</button></div> : null}
          <div className="activity-panel-footer"><span>Only confirmed blocks show source IPs. Older records may have no address. Payloads, full URLs, and credentials are not shown.</span><span>{available ? `${data.recentFailureCount ?? 0} Guard events in the last 60 seconds` : ""}</span></div>
        </section>

        <section className="activity-explain"><div><p className="activity-kicker">HOW THIS WORKS</p><h2>A real system, with clear boundaries.</h2></div><div className="activity-explain-grid"><article><b>01</b><h3>Observe</h3><p>The Exchange checks repeated API abuse against signed node requests and trusted client identity.</p></article><article><b>02</b><h3>Contain</h3><p>Application limits slow abusive requests. A connected HoneyMesh agent may hold a short local network ban.</p></article><article><b>03</b><h3>Share by choice</h3><p>Local blocks are not automatically sent to other networks. Shared intelligence requires separate review and opt-in policy.</p></article></div></section>
        <footer className="activity-footer"><span>HoneyMesh Exchange · Local activity view</span><Link href="/">honeymesh.io ↗</Link></footer>
      </div>
    </main>
  );
}

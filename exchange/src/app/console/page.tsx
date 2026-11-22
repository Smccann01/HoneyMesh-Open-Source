"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";

import "../activity/activity.css";
import "./console.css";

type Admin = { id: string; email: string; tenantId: string; clusterId: string };
type Policy = { receiveEnabled: boolean; exchangeOriginEnabled: boolean; mode: "observe" | "review" | "temporary"; minConfidence: number; maxTTL: number; updatedAt: string | null };
type Source = { clusterId: string; trusted: boolean; updatedAt: string };
type Event = { id: string; actorId: string; action: string; details: string; createdAt: string };
type NetworkStatus = { clusterId: string; enrolledNodes: number; accessActive: boolean; sharingEnabled: boolean; agentPolicyAcknowledged: boolean };

function describeEvent(event: Event) {
  try {
    const details = JSON.parse(event.details) as Record<string, unknown>;
    if (event.action === "source_trust.update") {
      return `${String(details.clusterId)}: ${details.trusted ? "trusted" : "paused"}`;
    }
    if (event.action === "receive_policy.update") {
      const next = details.next as Partial<Policy> | undefined;
      if (next) return `Network delivery ${next.receiveEnabled ? "on" : "off"} · Exchange-origin preference ${next.exchangeOriginEnabled ? "on" : "off"} · ${next.mode ?? "observe"} · confidence ${next.minConfidence ?? 90}+`;
    }
  } catch { /* Keep the log usable if an older entry has different details. */ }
  return "Policy updated";
}

const defaultPolicy: Policy = { receiveEnabled: false, exchangeOriginEnabled: false, mode: "observe", minConfidence: 90, maxTTL: 120, updatedAt: null };

async function api<T>(path: string, method = "GET", body?: object): Promise<T> {
  const response = await fetch(path, { method, cache: "no-store", credentials: "same-origin", headers: { "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error ?? "Request failed");
  return data as T;
}

export default function ConsolePage() {
  const [admin, setAdmin] = useState<Admin | null>(null);
  const [loading, setLoading] = useState(true);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [policy, setPolicy] = useState<Policy>(defaultPolicy);
  const [sources, setSources] = useState<Source[]>([]);
  const [sourceInput, setSourceInput] = useState("");
  const [events, setEvents] = useState<Event[]>([]);
  const [networkStatus, setNetworkStatus] = useState<NetworkStatus | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");

  const load = useCallback(async () => {
    const [policyData, sourceData, auditData, statusData] = await Promise.all([
      api<{ policy: Policy }>("/api/admin/policy"),
      api<{ sources: Source[] }>("/api/admin/sources"),
      api<{ events: Event[] }>("/api/admin/audit"),
      api<NetworkStatus>("/api/admin/status"),
    ]);
    setPolicy(policyData.policy); setSources(sourceData.sources); setEvents(auditData.events); setNetworkStatus(statusData);
  }, []);

  useEffect(() => {
    let mounted = true;
    api<{ admin: Admin }>("/api/admin/session").then(async (result) => {
      if (!mounted) return;
      setAdmin(result.admin); await load();
    }).catch(() => { if (mounted) setAdmin(null); }).finally(() => { if (mounted) setLoading(false); });
    return () => { mounted = false; };
  }, [load]);

  async function signIn(event: React.FormEvent) {
    event.preventDefault(); setBusy(true); setMessage("");
    try {
      const result = await api<{ admin: Admin }>("/api/admin/session", "POST", { email, password, code });
      setAdmin(result.admin); setPassword(""); setCode(""); await load();
    } catch { setMessage("Sign-in failed. Check your email, password, and authenticator code."); }
    finally { setBusy(false); }
  }

  async function savePolicy() {
    setBusy(true); setMessage("");
    try { const result = await api<{ policy: Policy }>("/api/admin/policy", "PUT", { receiveEnabled: policy.receiveEnabled, exchangeOriginEnabled: policy.exchangeOriginEnabled, mode: policy.mode, minConfidence: policy.minConfidence, maxTTL: policy.maxTTL }); setPolicy(result.policy); await load(); setMessage("Exchange delivery policy saved. Local HoneyMesh enforcement remains under the node's own controls."); }
    catch { setMessage("The policy could not be saved."); }
    finally { setBusy(false); }
  }

  async function saveSource(clusterId: string, trusted: boolean) {
    setBusy(true); setMessage("");
    try { const result = await api<{ sources: Source[] }>("/api/admin/sources", "PUT", { clusterId: clusterId.trim(), trusted }); setSources(result.sources); setSourceInput(""); await load(); setMessage(`Source ${clusterId} ${trusted ? "trusted" : "paused"} for Exchange delivery.`); }
    catch { setMessage("The source could not be saved. Check the cluster ID."); }
    finally { setBusy(false); }
  }

  async function signOut() {
    await api("/api/admin/session", "DELETE").catch(() => undefined);
    setAdmin(null); setPolicy(defaultPolicy); setSources([]); setEvents([]); setNetworkStatus(null); setMessage("");
  }

  return <main className="activity-page">
    <div className="activity-orbit activity-orbit-one" aria-hidden="true" />
    <div className="activity-wrap">
      <header className="activity-header"><Link className="activity-brand" href="/"><span className="activity-brand-mark" aria-hidden="true" /><span><strong>HONEY MESH</strong><small>NETWORK CONSOLE</small></span></Link><nav className="exchange-nav" aria-label="Main navigation"><Link href="/">About Exchange</Link><Link href="/downloads">Downloads</Link>{admin && <button className="console-text-button" onClick={signOut}>Sign out</button>}</nav></header>
      {loading ? <section className="console-login"><p>Checking admin session…</p></section> : !admin ? <section className="console-login"><p className="activity-kicker">NETWORK ADMIN</p><h1>Control who you trust.</h1><p>Sign in to set Exchange delivery choices and inspect your network&apos;s policy log.</p><form onSubmit={signIn} className="console-form"><label>Email<input type="email" autoComplete="username" required value={email} onChange={(event) => setEmail(event.target.value)} /></label><label>Password<input type="password" autoComplete="current-password" required value={password} onChange={(event) => setPassword(event.target.value)} /></label><label>Authenticator code<input inputMode="numeric" pattern="[0-9]{6}" maxLength={6} autoComplete="one-time-code" required value={code} onChange={(event) => setCode(event.target.value)} /></label><button disabled={busy}>Sign in</button></form>{message && <p role="alert">{message}</p>}</section> : <>
        <section className="activity-hero console-hero"><div className="activity-eyebrow">PRIVATE NETWORK CONSOLE</div><h1>Your network.<br /><em>Your trust policy.</em></h1><p>Signed Exchange relationships and your local HoneyMesh policy both matter. These controls filter Exchange delivery for <strong>{admin.clusterId}</strong>; the node still decides whether to enforce.</p><div className="exchange-download-note">Signed in as {admin.email} · Network {admin.clusterId}</div>{networkStatus && <p className="console-hint">Network status: {networkStatus.enrolledNodes} enrolled nodes · {networkStatus.accessActive ? "Free network access ready" : "Network access unavailable"} · {networkStatus.sharingEnabled ? "Sharing enabled" : "Sharing not enabled"}. Saved delivery choices take effect only when the network is eligible.</p>}</section>
        {message && <p className="console-message" role="status">{message}</p>}
        <div className="console-grid"><section className="activity-panel console-card"><div className="activity-panel-heading"><div><p className="activity-kicker">RECEIVING</p><h2>Exchange delivery</h2></div></div><div className="console-card-body"><label className="console-check"><input type="checkbox" checked={policy.receiveEnabled} onChange={(event) => setPolicy({ ...policy, receiveEnabled: event.target.checked })} /> Receive signals from explicitly trusted networks</label><label className="console-check"><input type="checkbox" checked={policy.exchangeOriginEnabled} onChange={(event) => setPolicy({ ...policy, exchangeOriginEnabled: event.target.checked })} /> Record opt-in for future Exchange-origin signals</label><div className="console-fields"><label>Requested local action<select value={policy.mode} onChange={(event) => setPolicy({ ...policy, mode: event.target.value as Policy["mode"] })}><option value="observe">Observe</option><option value="review">Review</option><option value="temporary">Temporary enforcement request</option></select></label><label>Minimum confidence<input type="number" min={80} max={100} value={policy.minConfidence} onChange={(event) => setPolicy({ ...policy, minConfidence: Number(event.target.value) })} /></label><label>Maximum TTL (seconds)<input type="number" min={60} max={300} value={policy.maxTTL} onChange={(event) => setPolicy({ ...policy, maxTTL: Number(event.target.value) })} /></label></div><p className="console-hint">Trusted-source delivery and minimum confidence are filtered by the Exchange server. Exchange-origin publication, TTL sync, agent acknowledgement, and local enforcement are not connected to this web console yet. The requested action is saved for the next integration stage.</p><button className="console-action" disabled={busy} onClick={savePolicy}>Save delivery policy</button></div></section>
        <section className="activity-panel console-card"><div className="activity-panel-heading"><div><p className="activity-kicker">SOURCES</p><h2>Trusted networks</h2></div></div><div className="console-card-body"><p>Only sources with a separate approved signals relationship can deliver. Trust here is directional: receiving their signals does not offer yours.</p><div className="console-source-add"><input aria-label="Source cluster ID" placeholder="Source cluster ID" value={sourceInput} onChange={(event) => setSourceInput(event.target.value)} /><button disabled={busy || !sourceInput.trim()} onClick={() => saveSource(sourceInput, true)}>Trust source</button></div>{sources.length ? <ul className="console-source-list">{sources.map((source) => <li key={source.clusterId}><span><strong>{source.clusterId}</strong><small>{source.trusted ? "Trusted for delivery" : "Paused"}</small></span><button disabled={busy} onClick={() => saveSource(source.clusterId, !source.trusted)}>{source.trusted ? "Pause" : "Trust"}</button></li>)}</ul> : <p className="console-empty">No networks trusted yet. The default is closed.</p>}</div></section></div>
        <section className="activity-panel console-audit"><div className="activity-panel-heading"><div><p className="activity-kicker">ADMIN LOG</p><h2>Policy changes</h2></div><span className="activity-refresh">Latest 100 entries</span></div>{events.length ? <div className="activity-table-wrap"><table><thead><tr><th>Time</th><th>Action</th><th>Details</th></tr></thead><tbody>{events.map((item) => <tr key={item.id}><td>{new Date(item.createdAt).toLocaleString()}</td><td>{item.action === "source_trust.update" ? "Source trust" : "Receive policy"}</td><td className="console-audit-details">{describeEvent(item)}</td></tr>)}</tbody></table></div> : <div className="activity-empty"><h3>No changes yet</h3><p>Saved trust and delivery choices will appear here.</p></div>}<div className="activity-panel-footer">This is the Exchange policy audit. Per-signal agent decisions will appear after agent acknowledgement and feedback are connected.</div></section>
      </>}
      <footer className="activity-footer"><span>HoneyMesh Exchange · Network console</span><Link href="/">honeymesh.io ↗</Link></footer>
    </div>
  </main>;
}

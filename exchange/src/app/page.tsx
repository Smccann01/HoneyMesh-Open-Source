import type { Metadata } from "next";
import Link from "next/link";

import "./activity/activity.css";

export const metadata: Metadata = {
  title: "HoneyMesh Exchange",
  description:
    "HoneyMesh Exchange is a private pilot for opt-in network discovery and short-lived signal sharing. Distributed enforcement qualification is ongoing.",
  alternates: { canonical: "/" },
};

export default function HomePage() {
  return (
    <main className="activity-page">
      <div className="activity-orbit activity-orbit-one" aria-hidden="true" />
      <div className="activity-orbit activity-orbit-two" aria-hidden="true" />
      <div className="activity-wrap">
        <header className="activity-header">
          <Link className="activity-brand" href="/" aria-label="HoneyMesh Exchange home">
            <span className="activity-brand-mark" aria-hidden="true" />
            <span><strong>HONEY MESH</strong><small>THE EXCHANGE</small></span>
          </Link>
          <a className="activity-home-link" href="https://network-decode.com/products">Explore HoneyMesh products <span aria-hidden="true">↗</span></a>
        </header>

        <section className="activity-hero exchange-home-hero">
          <div className="activity-eyebrow"><span className="activity-live-dot" /> HONEY MESH EXCHANGE · PRIVATE PILOT</div>
          <h1>Stronger defense<br /><em>through connection.</em></h1>
          <p>HoneyMesh agents pair deception traps with eBPF/XDP packet controls. In the private Exchange pilot, participating networks can evaluate signed, short-lived signal sharing under their own local policies. Distributed enforcement is still being qualified and is outside the paid Core Beta.</p>
          <div className="exchange-home-actions">
            <Link className="exchange-home-primary" href="/activity">View Exchange activity <span aria-hidden="true">↗</span></Link>
            <Link className="exchange-home-secondary" href="/downloads">Paid Core Beta <span aria-hidden="true">↗</span></Link>
            <a className="exchange-home-secondary" href="https://network-decode.com/pricing">Paid beta pilot <span aria-hidden="true">↗</span></a>
            <a className="exchange-home-secondary" href="https://network-decode.com/validation">Technical validation <span aria-hidden="true">↗</span></a>
            <Link className="exchange-home-secondary" href="/console">Network admin console <span aria-hidden="true">↗</span></Link>
            <a className="exchange-home-secondary" href="https://network-decode.com/docs">Read the docs <span aria-hidden="true">↗</span></a>
          </div>
        </section>

        <section className="activity-explain exchange-home-explain">
          <div><p className="activity-kicker">BUILT FOR CONTROL</p><h2>Participation is a choice.</h2></div>
          <div className="activity-explain-grid">
            <article><b>01</b><h3>Opt in</h3><p>Pilot operators decide whether their clusters appear in discovery. Hidden networks stay hidden.</p></article>
            <article><b>02</b><h3>Connect directly</h3><p>Pilot networks can establish bilateral sharing after both sides approve and configure trust.</p></article>
            <article><b>03</b><h3>Use the Exchange</h3><p>Eligible pilot peers can receive approved, short-lived signals through signed machine APIs; each node decides whether to enforce.</p></article>
          </div>
        </section>
        <footer className="activity-footer"><span>HoneyMesh Exchange · honeymesh.io</span><a href="https://network-decode.com/">About HoneyMesh ↗</a></footer>
      </div>
    </main>
  );
}

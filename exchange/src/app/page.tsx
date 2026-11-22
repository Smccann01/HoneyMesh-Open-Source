import type { Metadata } from "next";
import Link from "next/link";

import "./activity/activity.css";

export const metadata: Metadata = {
  title: "HoneyMesh Exchange Community | Self-hosted intelligence",
  description:
    "Operate your own HoneyMesh Exchange with local administration, opt-in sharing, and no Network Decode hosted subscription.",
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
          <div className="activity-eyebrow"><span className="activity-live-dot" /> HONEY MESH EXCHANGE · SELF-HOSTED COMMUNITY</div>
          <h1>One Node Detects.<br /><em>The Network Learns.</em></h1>
          <p>Operate an Exchange for networks you control. Enroll nodes with one-use administrator tokens, share eligible short-lived observations only when you opt in, and keep every enforcement decision at the receiving node. Your private Exchange needs no Network Decode subscription.</p>
          <div className="exchange-home-actions">
            <Link className="exchange-home-primary" href="/console">Open your private console <span aria-hidden="true">↗</span></Link>
            <Link className="exchange-home-secondary" href="/downloads">Choose a node path <span aria-hidden="true">↗</span></Link>
            <a className="exchange-home-secondary" href="https://network-decode.com/private-exchange">Run your own Exchange <span aria-hidden="true">↗</span></a>
            <a className="exchange-home-secondary" href="https://network-decode.com/products/honeymesh-exchange">Explore hosted membership <span aria-hidden="true">↗</span></a>
          </div>
          <p>Network observations and block data stay in authenticated services. This public page does not show live activity.</p>
        </section>

        <section className="activity-explain exchange-home-explain">
          <div><p className="activity-kicker">BUILT FOR CONTROL</p><h2>Participation is a choice.</h2></div>
          <div className="activity-explain-grid">
            <article><b>01</b><h3>Opt in</h3><p>Operators decide whether their clusters appear in discovery. Hidden networks stay hidden.</p></article>
            <article><b>02</b><h3>Connect directly</h3><p>Networks can establish bilateral sharing after both sides approve and configure trust.</p></article>
            <article><b>03</b><h3>Use the Exchange</h3><p>Eligible peers can receive approved, short-lived signals through signed machine APIs; each node decides whether to enforce.</p></article>
          </div>
        </section>
        <footer className="activity-footer"><span>HoneyMesh Exchange · honeymesh.io</span><a href="https://network-decode.com/">About HoneyMesh ↗</a></footer>
      </div>
    </main>
  );
}

import type { Metadata } from "next";
import Link from "next/link";

import "../activity/activity.css";

export const metadata: Metadata = {
  title: "HoneyMesh downloads | Core pilot and HoneyMesh 2.0",
  description: "Choose the free Core pilot or the separate signed HoneyMesh 2.0 node package.",
  alternates: { canonical: "/downloads" },
};

export default function DownloadsPage() {
  return (
    <main className="activity-page">
      <div className="activity-wrap">
        <header className="activity-header">
          <Link className="activity-brand" href="/" aria-label="HoneyMesh Exchange home">
            <span className="activity-brand-mark" aria-hidden="true" />
            <span><strong>HONEY MESH</strong><small>THE EXCHANGE</small></span>
          </Link>
          <nav className="exchange-nav" aria-label="Main navigation"><Link href="/console">Private console</Link><a href="https://network-decode.com/products">Products ↗</a></nav>
        </header>

        <section className="activity-hero exchange-download-hero">
          <div className="activity-eyebrow">HONEY MESH · CURRENT PATHS</div>
          <h1>Choose your node.<br /><em>Keep your control.</em></h1>
          <p>The original HoneyMesh Core pilot and this self-hosted Exchange are available from public source. HoneyMesh 2.0 is a separate signed, paid node package. Neither local operation nor a private Exchange requires Network Decode hosted membership.</p>
        </section>

        <section className="activity-explain exchange-download-resources">
          <div><p className="activity-kicker">PRODUCT PATHS</p><h2>Start with the right package.</h2></div>
          <div className="activity-explain-grid">
            <article><b>01</b><h3>Free Core pilot</h3><p>Use the free source or the current noncritical Ubuntu 24.04 AMD64 pilot. Start in TEST and verify the release guidance before attaching an interface.</p><a href="https://network-decode.com/downloads">Get the Core pilot ↗</a></article>
            <article><b>02</b><h3>Private Exchange</h3><p>Build the public AGPL-3.0-only Exchange source, create an administrator locally, and enroll nodes with one-use tokens. Sharing starts off.</p><a href="https://github.com/Smccann01/HoneyMesh-Open-Source/tree/main/exchange">Get Exchange source ↗</a></article>
            <article><b>03</b><h3>HoneyMesh 2.0</h3><p>The signed `.deb` preview costs $45 per original node. Hosted Exchange access is a separate $5-per-node monthly membership; check the current subscription status before planning a hosted deployment.</p><a href="https://network-decode.com/products/honeymesh-2">View HoneyMesh 2.0 ↗</a></article>
          </div>
        </section>

        <footer className="activity-footer"><span>HoneyMesh Exchange · Download paths</span><Link href="/">Exchange home ↗</Link></footer>
      </div>
    </main>
  );
}

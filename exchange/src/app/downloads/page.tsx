import type { Metadata } from "next";
import Link from "next/link";

import "../activity/activity.css";

export const metadata: Metadata = {
  title: "HoneyMesh Core Beta Download",
  description: "Register for the signed HoneyMesh Core Beta for Ubuntu 24.04 AMD64 and read the version-matched setup guide.",
  alternates: { canonical: "/downloads" },
};

const packages = [
  { format: "DEB", platform: "Ubuntu / Debian", file: "honeymesh_2.3.6-rc3-Iron-Hive_amd64.deb", sha256: "4d0054126bb5faa394f8baaae6743e5f47a2638b48a48e473bd56e48b0f0702b" },
  { format: "RPM", platform: "RHEL / Rocky / Fedora", file: "honeymesh-2.3.6-1.rc3_Iron_Hive.x86_64.rpm", sha256: "397a9c39d3af9893f50f8e4a02b8fd8044e70d6e016c159dc6b187428ee8f290" },
  { format: "TAR.GZ", platform: "Manual Linux install", file: "honeymesh-2.3.6-rc3-Iron-Hive-linux-amd64.tar.gz", sha256: "fc62be0a7c10422c92eadffd357485bae5c04a7239fbbcf80f187eb1ee58c23b" },
];

export default function DownloadsPage() {
  return (
    <main className="activity-page">
      <div className="activity-orbit activity-orbit-one" aria-hidden="true" />
      <div className="activity-wrap">
        <header className="activity-header">
          <Link className="activity-brand" href="/" aria-label="HoneyMesh Exchange home">
            <span className="activity-brand-mark" aria-hidden="true" />
            <span><strong>HONEY MESH</strong><small>THE EXCHANGE</small></span>
          </Link>
          <nav className="exchange-nav" aria-label="Main navigation"><Link href="/activity">Live defense</Link><a href="https://network-decode.com/products">Products ↗</a><a href="https://network-decode.com/get-started">Get started ↗</a></nav>
        </header>

        <section className="activity-hero exchange-download-hero">
          <div className="activity-eyebrow">HONEY MESH CORE · PUBLIC BETA</div>
          <h1>Detect locally.<br /><em>Enforce carefully.</em></h1>
          <p>HoneyMesh Core Beta brings deception-triggered detection and eBPF/XDP controls to Ubuntu 24.04 AMD64. The signed RC4 package starts in TEST. A paid HoneyMesh subscription and verified billing email are required to download it from Network Decode.</p>
          <div className="exchange-download-highlights" aria-label="HoneyMesh capabilities"><span>TCP trap detection</span><span>Temporary local bans</span><span>Operator rollback</span></div>
          <div className="exchange-download-note">Beta evaluation · Generic XDP tested · Exchange sharing and Node Guard excluded</div>
        </section>

        <section className="exchange-download-section" aria-labelledby="packages-heading">
          <div className="activity-panel-heading exchange-download-heading"><div><p className="activity-kicker">SIGNED CORE BETA</p><h2 id="packages-heading">Start with the RC4 Debian package</h2></div><span className="activity-refresh">Ubuntu 24.04 · AMD64 · 2.3.6-rc4</span></div>
          <div className="exchange-download-body">
          <p>For development and noncritical evaluation. Controlled tests show IPv4/IPv6 trap-triggered blocking, expiry, reboot recovery, and normal reference API traffic. General production qualification remains open.</p>
          <a className="exchange-package-download" href="https://network-decode.com/beta">View paid Core Beta access <span aria-hidden="true">↗</span></a>
          <p><a href="https://network-decode.com/get-started">Administrator setup path ↗</a> · <a href="https://network-decode.com/downloads/HoneyMesh-Core-Beta-rc4-Quickstart.md">Version-matched quickstart ↗</a> · <a href="https://network-decode.com/validation">Technical validation ↗</a> · <a href="https://network-decode.com/downloads/HoneyMesh-Core-Beta-rc4-manifest.json">Signed release manifest ↗</a></p>
          <p>The current paid beta download is the signed Debian package. RC4 RPM and tar build outputs appear in the manifest but are not offered as beta downloads while their install paths remain unqualified.</p>
          <p>Teams seeking a paid, noncritical Infrastructure Pro beta pilot can review the <a href="https://network-decode.com/pricing">$15/month per-host terms ↗</a>. Distributed Pro capabilities remain under qualification.</p>
          </div>
        </section>

        <section className="exchange-download-section" aria-labelledby="historical-heading">
          <div className="activity-panel-heading exchange-download-heading"><div><p className="activity-kicker">HISTORICAL</p><h2 id="historical-heading">Earlier RC3 candidate</h2></div><span className="activity-refresh">Not the current Core Beta</span></div>
          <details className="exchange-history">
            <summary>Show historical RC3 packages</summary>
          <p>These records remain for release history. Package binaries are no longer public downloads.</p>
          <div className="exchange-package-grid">
            {packages.map((item) => <article className="exchange-package" key={item.file}>
              <span className="exchange-package-format">{item.format}</span>
              <h3>{item.platform}</h3>
              <p className="exchange-package-file">{item.file}</p>
              <span className="exchange-package-archived">Archived package</span>
              <div className="exchange-package-hash"><span>SHA-256</span><code>{item.sha256}</code></div>
            </article>)}
          </div>
          </details>
        </section>

        <section className="activity-explain exchange-download-resources">
          <div><p className="activity-kicker">BEFORE YOU INSTALL</p><h2>Verify. Observe. Recover.</h2></div>
          <div className="activity-explain-grid">
            <article><b>01</b><h3>Check authenticity</h3><p>Verify the RC4 <a href="https://network-decode.com/downloads/HoneyMesh-Core-Beta-rc4-manifest.asc">publisher signature ↗</a> and the Debian package hash.</p></article>
            <article><b>02</b><h3>Start in TEST</h3><p>Follow the <a href="https://network-decode.com/downloads/HoneyMesh-Core-Beta-rc4-Quickstart.md">RC4 beta quickstart ↗</a> on a noncritical Ubuntu 24.04 AMD64 host.</p></article>
            <article><b>03</b><h3>Keep a recovery route</h3><p>Protect management access and confirm the emergency XDP detach and service stop steps before ENFORCE.</p></article>
          </div>
        </section>
        <footer className="activity-footer"><span>HoneyMesh Exchange · Download center</span><Link href="/">honeymesh.io ↗</Link></footer>
      </div>
    </main>
  );
}

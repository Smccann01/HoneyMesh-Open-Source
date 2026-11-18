# HoneyMesh Operator Manual

PDF edition for the 2.3.6-rc2 AMD64 release candidate. Check your installed package and host distribution before applying changes.

Date: 2026-10-30  
Version: v2.3.6-rc2-Iron-Hive

This manual covers the current HoneyMesh operator workflow for local protection, Pro licensing, HoneyMesh Exchange connectivity, trusted mesh discovery, per-network trust, temporary join tokens, and day-to-day administration.

---

**1. Overview**

HoneyMesh is a distributed defense platform built around three layers:

- Local traps and analytics to observe hostile activity.
- Local kernel packet enforcement through eBPF/XDP. The current implementation requests generic XDP mode; do not assume hardware offload or a particular throughput.
- Optional Pro-only shared defense through HoneyMesh Exchange and trusted mesh participation.

HoneyMesh Exchange is an optional discovery and intelligence plane. It helps operators discover other HoneyMesh cluster IDs and receive shared attack intelligence when they explicitly opt in. Direct trust and peer federation still stay under operator control.

Trusted mesh participation is the peer-to-peer layer. It is how approved HoneyMesh networks exchange validated defense signals after an operator chooses which external networks to trust and at what level.

---

**2. Requirements**

Runtime requirements:

- Linux kernel 5.8 or newer (required for the service's `CAP_BPF` and `CAP_PERFMON` capabilities).
- Root privileges for installation; the packaged service runs as the dedicated `honeymesh` user with bounded BPF/network capabilities.
- HTTPS certificates for the dashboard/API if you run outside a lab.
- OpenSSL for package installation; the installer creates a unique local CA and node certificate.
- Go 1.26.10 only if building from source; not required to run the packages.

Installed package layout:

- Binary: `/usr/bin/honeymesh`
- Primary config: `/etc/honeymesh/honeymesh.json`
- Local data/state: `/var/lib/honeymesh/`
- Dashboard assets: `/usr/share/honeymesh/web/`
- eBPF source archive: `/usr/share/honeymesh/ebpf-src.tar.gz`

Common local files used at runtime:

- License file: `license.json`
- Cluster identity: `cluster.id`
- Mesh signing identity: `identity.key`

---

**3. Install And Run**

Build from source:

```bash
cd /path/to/HoneyMesh-2.3.6-rc2
GOTOOLCHAIN=go1.26.10 go build -o honeymesh .
```

The source archive can be built for development. The package instructions below are the supported service path.

Install the current Debian package:

```bash
sudo dpkg -i /path/to/honeymesh_2.3.6-rc2-Iron-Hive_amd64.deb
```

The package installs a Community configuration bound to `127.0.0.1`, with no interfaces or traps selected and sharing disabled. On a systemd host, a fresh install starts the service. Edit `/etc/honeymesh/honeymesh.json` to choose the interfaces and traps you intend to protect, then run `sudo systemctl restart honeymesh.service`; the service detects the operator config change and applies those selections. The configuration is root-owned and readable by the `honeymesh` service group. The first start saves a unique admin token in `/var/lib/honeymesh/runtime-state.json` (mode `0600`). The installer generates local TLS certificates per machine; for remote dashboard access or trusted mesh, configure certificates and CA trust for the actual network names and addresses. Never copy another node's private key or live configuration into an installation package.

Run the packaged service:

```bash
sudo systemctl enable --now honeymesh.service
```

Startup banner:

```text
🍯  Honey Mesh v2.3.6-rc2-Iron-Hive Active
```

Generate a temporary trusted mesh invite token:

```bash
sudo runuser -u honeymesh -- /usr/bin/honeymesh -config /etc/honeymesh/honeymesh.json -state-dir /var/lib/honeymesh -token
```

Join another HoneyMesh network with a temporary token:

```bash
sudo runuser -u honeymesh -- /usr/bin/honeymesh -config /etc/honeymesh/honeymesh.json -state-dir /var/lib/honeymesh -join https://<PEER_IP>:9000/mesh/join -t <TEMP_TOKEN>
```

Manual exchange enrollment flow:

```bash
sudo runuser -u honeymesh -- /usr/bin/honeymesh -config /etc/honeymesh/honeymesh.json -state-dir /var/lib/honeymesh -register-exchange https://nettools.cloud -enroll-token <ENROLL_TOKEN>
```

Operator flow for an Exchange deployment:

- Upload a valid Pro `license.json` in the app.
- Confirm `exchange.base_url` points to the intended Exchange deployment; packaged defaults may still point to a legacy endpoint.
- Open `TRUSTED PEERS` and enable Exchange sharing.
- Confirm the actual connected status and review discovered clusters before trusting them.

Uninstall:

```bash
sudo systemctl stop honeymesh || true
sudo systemctl disable honeymesh || true
sudo dpkg -r honeymesh
```

Back up private config and state before any package removal. Package removal may leave valuable state in place.

---

**4. Admin Token**

The dashboard and operator API require an admin token.

Behavior:

- If `admin_token` is empty, HoneyMesh generates one at startup.
- The generated token is saved to `/var/lib/honeymesh/runtime-state.json` on first start. Keep it out of logs, screenshots, and support messages. The operator config may also specify a token.
- API requests use the `X-Honey-Token` header.

---

**5. Licensing And Feature Gates**

License tiers:

- `COMMUNITY`: Local-only protection, local dashboard, local analytics, no Exchange participation, no trusted mesh participation.
- `PRO`: Community features plus premium dashboard controls, HoneyMesh Exchange opt-in, trusted mesh participation, and shared defense features.

Important behavior:

- Pro sharing features are off by default.
- Operators must explicitly enable them.
- If the Pro license is invalid or expired, HoneyMesh disables Exchange and trusted mesh participation immediately.
- HoneyMesh validates the signed license locally before enabling Pro-only capabilities.

Current shared-defense model:

- `NetTools.cloud Sharing` is the in-app toggle that enables HoneyMesh Exchange integration.
- HoneyMesh Exchange is used to discover cluster IDs and receive curated/shared attack intelligence.
- `Trusted Mesh Networks` is a separate control for direct peer federation.
- Exchange discovery does not automatically trust another network.
- Operators choose trust network by network.

---

**6. Configuration (`honeymesh.json`)**

Top-level controls:

- `node_name`: Friendly node name shown in the UI and exchange registration.
- `bind_ip`: Dashboard and API bind address.
- `web_port`: Dashboard HTTPS port.
- `mesh_port`: Peer mesh port.
- `admin_token`: Optional operator-configured dashboard/API admin token. An automatically generated token resides in private runtime state.
- `license_tier`: Persisted effective tier state.
- `trusted_network_sharing_enabled`: Persisted Exchange opt-in state.
- `trusted_mesh_network_enabled`: Persisted trusted mesh participation state.

Mesh controls:

- `mesh.peers`: Known direct peers.
- `mesh.quorum`: Quorum ratio for mesh decisions.
- `mesh.min_peers`: Minimum expected peer count.
- `mesh.authoritative_peers`: Peer list treated as highly trusted.
- `mesh.trusted_networks`: Cluster-level trust policy list.

`mesh.trusted_networks` entries:

```json
{
  "cluster_id": "cid_example",
  "trust_level": 2
}
```

Exchange controls:

- `exchange.enabled`
- `exchange.base_url`
- `exchange.node_id`
- `exchange.tenant_id`
- `exchange.shared_secret`
- `exchange.trusted_clusters`
- `exchange.pull_interval_s`
- `exchange.push_local_bans`
- `exchange.pull_shared_feed`
- `exchange.trust_threshold`
- `exchange.feed_cursor`
- `exchange.last_registered_at`

Security controls:

- `security.allowlist_base`
- `security.whitelist`
- `security.trusted_peers`
- `security.ja4_blacklist`
- `security.ja4_labels`
- `security.ja3_blacklist`
- `security.ja3_labels`
- `security.mesh_event_rate_limit_per_min`
- `security.mesh_event_burst`
- `security.mesh_replay_window_s`
- `security.mesh_data_classification`
- `security.scan_ports`
- `security.scan_window_s`
- `security.trap_ban_hits`
- `security.trap_ban_window_s`

Notes:

- `exchange.trusted_clusters` controls which Exchange cluster IDs HoneyMesh accepts Exchange feed data from.
- `mesh.trusted_networks` controls how much HoneyMesh trusts a cluster after it becomes part of the trusted mesh workflow.
- HoneyMesh omits its own cluster ID from discovered external Exchange networks.

---

**7. Dashboard Layout**

The dashboard is a single-page operator console. In the current agent, XDP attachment requests generic XDP mode; kernel enforcement is available on supported interfaces, but line-rate performance is not guaranteed.

Header:

- Cluster ID
- License status pill
- Mode controls: `TEST MODE`, `ENFORCE`, `LOCKDOWN`

Main panels:

- `TRAPS`
- `INTERFACES`
- `HONEYMESH DEFENSE NETWORK`
- `LIVE THREAT STREAM`

Status summaries:

- License state
- `NetTools.cloud Sharing` state
- `Trusted Mesh Networks` state
- Exchange connection details

The UI now exposes whether the node is actually connected to HoneyMesh Exchange, not just whether the toggle is turned on.

---

**8. Traps Panel**

Purpose:

- Configure honeypot listeners.
- Tune local scan thresholds.
- Observe trap status quickly.

Controls:

- Trap enable/disable
- Watchdog mode
- Banner editing
- Scan threshold save controls

Trap states shown in the UI:

- `LISTENING`
- `WATCHDOG`
- `DISABLED`

---

**9. Interfaces Panel**

Purpose:

- Attach and detach XDP enforcement from local interfaces.

Per-interface controls:

- `ATTACH`
- `DETACH`

Displayed fields:

- Assigned IPs
- Link status
- Protection mode

---

**10. HoneyMesh Defense Network Panel**

Purpose:

- Manage local sharing state.
- Review trusted mesh posture.
- Generate invites.
- Join approved networks.

Header actions:

- `TRUST LEVELS`
- `TRUSTED PEERS`
- `TEMPORARY MESH INVITE`
- `JOIN WITH INVITE`

Status area:

- Current license state
- Exchange sharing state
- Trusted mesh participation state
- Exchange connectivity from `/api/health`

---

**11. Trusted Peers Modal**

This is now the main shared-defense control surface.

Sections include:

- `Enable NetTools.cloud Sharing`
- `HoneyMesh Exchange Trust`
- `Enable Trusted Mesh Participation`
- `Temporary Mesh Invite`
- `Join With Invite`
- Base allowlist toggle
- Allowlist editor
- Trusted peer editor

Exchange-specific details shown in the modal:

- Real connection status: `Connected to HoneyMesh Exchange` or `Not connected to HoneyMesh Exchange`
- Local cluster ID
- Trusted Exchange cluster IDs
- Observed Exchange cluster IDs

Observed Exchange cluster IDs:

- Are discovered through exchange traffic.
- Do not include this node’s own cluster ID.
- Can be reviewed before any trust decision is made.

Trusted Exchange cluster IDs:

- Control which Exchange-originated cluster feeds HoneyMesh will accept.
- Are useful when you want Exchange discovery but do not want to trust every connected cluster.

Save behavior:

- The sharing toggle now returns the real backend error if Exchange bootstrap fails.
- When Exchange bootstrap succeeds, HoneyMesh stores the returned node ID, tenant ID, and shared secret automatically.

---

**12. Trusted Mesh Networks**

Trusted mesh networks are cluster-level trust policies for peer federation.

HoneyMesh lets operators assign:

- `L0 OBSERVE`
- `L1 FEDERATED`
- `L2 TRUSTED`
- `L3 AUTHORITATIVE`

How to use them:

- Discover candidate cluster IDs through HoneyMesh Exchange.
- Add a cluster to trusted mesh policy.
- Set the trust level that matches your operational relationship.
- Use a temporary invite token to join approved peer networks.

Practical model:

- Exchange is for discovery and optional shared intelligence.
- Trusted mesh is for explicit peer-to-peer defense cooperation.
- The operator stays in control of both.

---

**13. Temporary Mesh Invites**

Temporary invites are the safe way to join another HoneyMesh network without handing out permanent admin credentials.

Generation:

- Open `TRUSTED PEERS`
- Use `TEMPORARY MESH INVITE`
- Choose a short TTL
- Copy the token

Join workflow:

- Open `JOIN WITH INVITE`
- Enter the peer address and token
- HoneyMesh performs the join against the remote mesh endpoint

API examples:

Create invite:

```bash
curl -k -X POST "https://<NODE_IP>:<WEB_PORT>/api/mesh/invite" \
  -H "X-Honey-Token: <ADMIN_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"ttl_minutes":30}'
```

Join with invite:

```bash
curl -k -X POST "https://<LOCAL_NODE_IP>:<LOCAL_WEB_PORT>/api/mesh/join" \
  -H "X-Honey-Token: <LOCAL_ADMIN_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"peer":"<PEER_IP>:9000","token":"<TEMP_TOKEN>"}'
```

---

**14. Live Threat Stream**

Purpose:

- Review recent hostile activity.
- Inspect active bans.
- Perform manual operator actions.

Events table columns:

- `TIME`
- `IP ADDRESS`
- `PORT`
- `JA4 / JA3 LEGACY`
- `APP`
- `SESSION`
- `ACTION`

Active bans table columns:

- `IP`
- `EXPIRES`
- `JA4 / JA3 LEGACY`
- `ACTION`

Common actions:

- `BLOCK`
- `ALLOW`
- `WHITELIST`
- `RELEASE`
- `EXTEND`
- `PERMANENT`

---

**15. JA4-First Fingerprinting**

HoneyMesh is JA4-first.

Behavior:

- JA4 is the primary TLS fingerprint in the UI and shared-defense paths.
- JA3 remains available as a compatibility field when present.
- Shared intelligence can carry JA4 plus legacy JA3 context.
- Remote data is only accepted after signature, replay-window, version, and rate-limit checks pass.

---

**16. API Endpoints**

Common operator endpoints:

- `GET /api/health`
- `GET /api/events`
- `GET /api/bans`
- `GET /api/bans/meta`
- `GET /api/license-info`
- `GET /api/security`
- `GET /api/peers`
- `POST /api/license`
- `POST /api/security`
- `POST /api/mode`
- `POST /api/ban`
- `POST /api/ban/extend`
- `POST /api/ban/release`
- `POST /api/allow`
- `POST /api/trap`
- `GET /api/ifaces`
- `POST /api/iface`
- `POST /api/mesh/invite`
- `POST /api/mesh/join`
- `POST /api/mesh/revoke`

`POST /api/security` is the main persistence endpoint for:

- allowlist settings
- trusted peers
- scan thresholds
- Exchange sharing enablement
- trusted Exchange cluster IDs
- trusted mesh network policies
- trusted mesh participation enablement

Headers:

- `X-Honey-Token: <ADMIN_TOKEN>`

---

**17. Troubleshooting**

Startup problems:

- `failed to raise memlock limit`: run as root or raise memlock.
- `license invalid` or `license expired`: HoneyMesh falls back to Community mode and disables Pro-only shared defense features.

Exchange toggle fails:

- Check that the node has a valid Pro license.
- Confirm outbound HTTPS reachability to the configured Exchange host.
- Check the exact error shown in the `TRUSTED PEERS` modal.
- If bootstrap fails, HoneyMesh now surfaces the backend error directly instead of a generic save failure.

Not connected to HoneyMesh Exchange:

- The toggle can be on while connectivity is still broken.
- Check `/api/health` and the Exchange status line in the modal.
- Verify `exchange.base_url`, `exchange.node_id`, `exchange.tenant_id`, and `exchange.shared_secret` in config after successful bootstrap.

No discovered networks:

- Exchange discovery only shows up after Exchange traffic returns other cluster IDs.
- Your own cluster ID is intentionally omitted from discovered external networks.

Trusted mesh join issues:

- Verify Pro mode.
- Verify `trusted_mesh_network_enabled` is on.
- Verify peer reachability and certificate trust.
- Verify the invite token is still valid.

UI not updating:

- Verify the admin token.
- Check browser console errors.
- Refresh `/api/health` and `/api/security` directly to confirm backend state.

---

**18. Operational Notes**

Security posture:

- In Enforce mode, an attached generic XDP program can drop banned IPv4 and IPv6 packets in the kernel. This does not imply native XDP, hardware offload, or a specific line rate.
- Exchange and trusted mesh are both opt-in.
- Shared signals are signed, replay-window checked, and rate limited.
- HoneyMesh federation is version-gated and rejects invalid or stale remote intelligence.

Operational guidance:

- Use Exchange to discover candidate cluster IDs.
- Use trusted mesh levels to formalize how much you trust another network.
- Use temporary invite tokens for onboarding instead of long-lived admin secrets.
- Keep Community nodes local-only unless you intentionally upgrade them.

---

**19. Quick Reference**

Common actions:

- `TEST MODE`: detect only
- `ENFORCE`: active blocking
- `LOCKDOWN`: aggressive enforcement
- `NetTools.cloud Sharing`: opt in to HoneyMesh Exchange
- `Trusted Mesh Networks`: opt in to direct peer federation
- `L0`: observe only
- `L1`: limited federated trust
- `L2`: trusted federated network
- `L3`: authoritative network
- `BLOCK`: manually ban from events
- `PERMANENT`: apply long-lived ban
- `RELEASE`: remove a ban


## 2.3.5 trusted mesh TLS migration

A 2.3.5 node that participates in a trusted mesh requires explicit TLS identity and CA trust. Each node needs its own private key and a certificate with `serverAuth` and `clientAuth` extended key usages. The certificate SAN must match the IP or DNS name that the node advertises to peers. The installer-generated localhost certificate is only for a standalone local installation.

Set `mesh.tls` in `/etc/honeymesh/honeymesh.json` before enabling `trusted_mesh_network_enabled` or running `-join`:

```json
"mesh": {
  "peers": [],
  "trusted_networks": [],
  "tls": {
    "cert_file": "certs/mesh/node.crt",
    "key_file": "certs/mesh/node.key",
    "peer_ca_file": "certs/mesh/peer-ca-bundle.crt",
    "client_ca_file": "certs/mesh/client-ca-bundle.crt"
  }
}
```

Paths are relative to the config file directory. `peer_ca_file` verifies outbound peer servers; `client_ca_file` verifies inbound client certificates. A common organizational CA can appear in both bundles, while every node still has a unique key. Keep private keys on their own nodes. The join token authorizes enrollment but does not replace TLS server authentication. When `-token` generates an invite, read it from `/var/lib/honeymesh/join.token` on a packaged installation; startup logs contain only its expiry.

Before upgrading an existing mesh, provision matching SAN certificates and distribute the trust bundles to all nodes. Include both old and new trusted CAs during a CA rotation, restart and verify peer connections, then remove the old CA after every peer uses the new certificate. Coordinate restarts because a 2.3.5 node rejects peers whose certificate chain is not in its configured bundle. Enabling trusted mesh through the dashboard requires a restart after editing the config file.

The dashboard WebSocket uses a 15-minute HTTPS session cookie. Operators still enter the admin token in the dashboard, but the browser does not place that token in the WebSocket URL. The CSV export prefixes spreadsheet formula cells with a tab.

## 2.3.6 system service migration

Packages now install `honeymesh.service`, a static `honeymesh` system account, and a private `/var/lib/honeymesh` state directory. On a systemd host, the installer enables and starts one service after migration unless it detects a manually started HoneyMesh process. Stop that manual process, then run `sudo systemctl enable --now honeymesh.service` to hand over. Use `systemctl status honeymesh.service` and `journalctl -u honeymesh.service` to inspect startup.

The service runs with `User=honeymesh`, bounded BPF/network capabilities, and `NoNewPrivileges=yes`. It is independent of human logins. The dashboard remains protected by the admin token; local OS accounts do not automatically gain access. The root-owned config and node TLS key are readable by the `honeymesh` group but not writable by the service. New admin tokens and dashboard-edited settings are stored in `/var/lib/honeymesh/runtime-state.json` (mode `0600`), while `/etc/honeymesh/honeymesh.json` remains operator-managed. The runtime state retains generated credentials and dashboard settings across restart; when the operator config changes, its interface, trap, and security selections take precedence. Edit the runtime state only through the dashboard or supported CLI flows.

The installer backs up the pre-migration config and state under `/var/backups/honeymesh/pre-236.*` before changing ownership. It rejects symlinks and hard-linked state files. It preserves existing certificate and configuration bytes on upgrade. For rollback to 2.3.5, stop and disable `honeymesh.service`, restore the backup config/state if necessary, then install the older package and start it manually. The `drop_privileges` config key is obsolete: the service account determines runtime identity. A root-launched daemon with `drop_privileges=true` now exits with a migration message.

On systems without systemd, package installation prepares the account and files without starting a daemon. Start it with the same account and capability policy used by the service unit. A plain `runuser` invocation without capabilities is insufficient for XDP protection.

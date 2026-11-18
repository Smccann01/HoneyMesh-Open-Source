# HoneyMesh Architecture (Deep Dive)

## 1. Executive Summary
HoneyMesh is a distributed cybersecurity platform that detects, analyzes, and blocks malicious network activity across a trust-scored mesh of nodes. Each node senses attacks locally, enforces policy at kernel speed using eBPF/XDP, and can participate in the HoneyMesh Defense Network for structured, sanitized attack-intelligence sharing. The system is designed for air-gapped and hostile environments: no central controller is required, and local protection continues even when external connectivity is lost.

## 2. Core Design Principles
- **Decentralization**: Each node is sovereign. Mesh federation is additive, not required.
- **Immediate Enforcement**: XDP/eBPF moves drop decisions to the earliest possible point.
- **Shared Intelligence**: Trusted Network Sharing propagates structured attack intelligence and ban/allow signals over a trust-scored mesh.
- **Fail‑Open Safety**: If the daemon exits, XDP detaches and traffic resumes.
- **Modularity**: Clear separation between control plane, detection, enforcement, federation, licensing, and data persistence.

## 3. Key Capabilities
### 3.1 Detection
- High‑interaction honeypot traps (TCP/UDP)
- Port scan detection with temporal correlation
- TLS client fingerprint handling with JA4 primary and JA3 legacy fallback
- Payload entropy analysis and pattern‑based scoring

### 3.2 Enforcement
- Kernel‑level packet dropping via XDP/eBPF maps
- Persistent local ban list (SQLite)
- Interface‑level attach/detach with local enforcement controls

### 3.3 Federation
- P2P mesh with join tokens and mutual TLS
- Trusted Network Sharing gated by Pro license plus explicit operator opt-in
- Stable node identity backed by an Ed25519 signing key
- `v2` peer capability exchange during join and heartbeat
- Structured, sanitized attack-intelligence ban signals shared across peers
- Per-event signatures, replay protection, and per-publisher rate limiting
- Explicit data-classification levels for shared intelligence payloads
- Authoritative allow overrides for safe unblocking

### 3.4 Control and Visibility
- Secure web dashboard + API
- Optional local TUI
- Real‑time event stream (websocket)
- BTL trust transparency and manual peer penalty

### 3.5 Licensing and Policy
- Ed25519‑signed licenses with offline verification
- Clock rollback detection via `license.clock`
- Two-tier model: Community and Pro
- Local protection available in Community and Pro
- Trusted Network Sharing available only in Pro and disabled by default until explicitly enabled
- Modes: TEST / ENFORCE / LOCKDOWN

## 4. System Architecture (Layers → Code)
- **Dashboard Layer**: `dashboard.go`, `web/index.html`
- **Control Plane**: `main.go`, `globals.go`, `runtime.go`, `policy.go`, `bootstrap.go`, `helpers.go`, `license_access.go`
- **Detection Layer**: `runtime.go`, `trap_protocols.go`, `ringbuf_reader.go`, `tls_fingerprint.go`
- **Enforcement Layer**: `enforcement.go`, `bpf/main.c`, `bpf_x86_bpfel.go`, `bpf_x86_bpfel.o`
- **Federation Layer**: `internal/mesh/`, `mesh_tokens.go`, `federation_security.go`, mesh wiring in `main.go`, `trust.go`, `mesh_intel.go`
- **License and Policy Engine**: `internal/license/`, `policy.go`
- **Data Layer**: `storage.go` (SQLite)

## 5. Software Structure (Repo Layout)
- `main.go`: entry point and system initialization
- `globals.go`: config and global runtime state
- `runtime.go`: event pipeline, detection logic, workers
- `tls_fingerprint.go`: TLS ClientHello parsing and JA4 / JA3 generation
- `enforcement.go`: XDP attach/detach and ban map operations
- `policy.go`: enforcement policy and duration logic
- `helpers.go`: utilities (entropy, fingerprint normalization helpers, IP helpers)
- `trap_protocols.go`: protocol‑specific trap responders
- `ringbuf_reader.go`: kernel ringbuf reader for telemetry
- `dashboard.go`: HTTPS dashboard + API endpoints
- `tui.go`: local text UI
- `mesh_tokens.go`: join token management
- `storage.go`: SQLite schema and persistence
- `bpf/main.c`: XDP program source
- `internal/mesh/`: federation logic (ban/allow, join, heartbeat)
- `internal/license/`: license verification and clock enforcement

## 6. Operational Flows
### 6.1 System Initialization
1. Parse flags and load configuration.
2. Load/verify license and cluster ID.
3. Initialize in-memory state, fingerprint caches, and eBPF objects.
4. Initialize SQLite and load history/bans/trust.
5. Start background workers and traps.
6. Start mesh server and connect to peers when Trusted Network Sharing is enabled.
7. Attach XDP to configured interfaces using local protection mode.
8. Start dashboard or TUI.

### 6.2 Detection Workflow
1. Trap receives connection or payload.
2. Event emitted into log pipeline.
3. TLS ClientHello parsing attempts JA4 generation and retains JA3 as a legacy fallback.
4. Scan tracking, entropy checks, and JA4-first / JA3-legacy fingerprint logic run.
5. Event stored and broadcast to UI.
6. Enforcement triggered if policy allows.

### 6.3 Enforcement Workflow
1. Policy gate checks operating mode.
2. IP added to in‑memory ban list.
3. Ban persisted to SQLite.
4. Ban inserted into eBPF map.
5. Structured ban intelligence broadcast to trusted peers when sharing is enabled.

### 6.4 Federation Workflow
1. Node joins mesh with token, mTLS, and a signed Pro capability claim.
2. Heartbeats refresh peer liveness and capability state.
3. Local bans can emit sanitized attack-intelligence signals containing JA4 primary and JA3 legacy context.
4. Each shared event carries the `v2` schema version, event ID, publisher node ID, timestamp, classification level, capability claim, and Ed25519 signature.
5. Receivers validate entitlement, schema version, publisher identity, freshness, replay state, signature, and rate limits before the signal reaches trust evaluation.
6. Accepted remote intelligence is gated by BTL trust, then emitted back into the local event pipeline for analytics and visibility.
7. Authoritative peers can broadcast allow overrides.

### 6.5 Trust (BTL) Workflow
1. Each peer has a trust score and BTL level (L0‑L3).
2. L0: observe only.
3. L1: require corroboration from another L1+ peer.
4. L2: immediate enforcement.
5. L3: global override (ban or allow).
6. Trust decays over time; manual penalties reduce trust.

### 6.6 Shutdown Procedure
1. Shutdown signal received.
2. Background workers stopped.
3. XDP programs detached.
4. Database closed.

## 7. Security Model
- TLS‑encrypted mesh communication with mTLS.
- Admin token required for API access.
- Ed25519 license verification and clock rollback detection.
- Shared intelligence is disabled unless both Pro licensing and explicit operator opt-in are active.
- Shared intelligence payloads avoid raw sensitive customer payload disclosure by default and are classified into `L1` to `L4` sharing levels.
- Federation messages are individually signed and verified independently of the transport session.
- Unsigned, unversioned, or non-`v2` federation payloads are rejected fail-closed.
- Replay protection rejects duplicate or stale event IDs per publisher.
- Abuse controls enforce per-publisher burst and per-minute limits.
- Mesh participation is scoped to valid Pro-sharing peers and matching cluster identity when configured.
- BTL trust model prevents poisoning from external peers.

## 8. Deployment Model
- Community mode: local protection, dashboard/TUI, no trusted network participation.
- Pro mode: local protection plus premium controls and optional Trusted Network Sharing.
- Cluster mode: peer mesh with trust-scored shared intelligence when opted in.

## 9. Requirements
- Go 1.21+
- Linux kernel 5.4+ (for XDP/eBPF)
- SQLite (via `modernc.org/sqlite`)

## 10. Notes on Gaps vs Original Spec
- `models.go` is not present; fingerprinting functionality lives in `globals.go`, `runtime.go`, `helpers.go`, and `tls_fingerprint.go`.
- `cmd/license-gen/` is not present in this tree.

## 11. Why It Scales
HoneyMesh shifts enforcement into XDP where the kernel has not yet spent CPU on packet processing. This turns defense into a constant‑time, line‑rate decision. Under volumetric attack, the system does not collapse under load because it avoids the expensive path entirely. The control plane updates maps, not rules, enabling immediate response with no rule reloads.

## 12. One‑Sentence Summary
HoneyMesh is a distributed network defense system that **detects locally, enforces at line‑rate, and shares trust‑scored intelligence across a decentralized mesh**.

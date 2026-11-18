# Release readiness and host support

The repository is open source and can be built locally. The packages in this repository are not yet a qualified, signed general release. Do not attach a protected production interface until you have verified a host-specific recovery path.

## Evidence as of 2026-11-18

| Component | Build and test environment | Verified here | Still required for general availability |
| --- | --- | --- | --- |
| Core | Ubuntu 24.04.5, Linux 7.0, AMD64; Go 1.26.10 toolchain | `go test ./...`; AMD64 and ARM64 cross-builds; DEB, RPM and tar package content checks; matching SHA-256 hashes across two builds of all six packages | Clean-host install, upgrade, rollback and removal; ARM64 runtime; release signatures |
| Node agent | Same AMD64 host and Go toolchain | `go test ./...` | Clean-host install and recovery; two-host observation pilot |
| Node Guard | Node.js 22 on the same host | 40 tests | Application integration on supported Node.js versions |
| Self-hosted Exchange | Node.js 22, SQLite native module on the same host | Production build; admin, discovery and protocol integration tests | Restore drill and two-host network pilot |
| Firewall Console | Node.js 22 on the same host | 32 tests | Clean-host installation with an agent and recovery drill |

Core requires Linux kernel 5.8 or newer and a mounted BPF filesystem. A successful cross-build does not establish runtime support on another CPU or distribution. We currently have no qualification result for older kernels, other Linux distributions, or Windows hosts. The package pre-install check and manual list additional prerequisites.

## Release gates

1. Build packages twice from the same source revision and toolchain, then compare SHA-256 hashes for every format. This passed locally on the environment above; repeat it in CI and record the source revision and toolchain versions for a release.
2. Verify package contents contain no private key, cluster identity, live configuration, or operator credentials.
3. Sign the exact release artifacts and publish the signing identity, checksums, and verification instructions. An unsigned local build is not an official signed release.
4. On disposable supported hosts, prove install, TEST-mode start, upgrade, rollback, uninstall, and data restore. Keep independent access to each host throughout.
5. With two noncritical hosts, verify explicit admission, short-lived enrollment, observation delivery, replay resistance, expiry, revocation, source removal, and local enforcement authority. Record false positives and recovery time before expanding the network.

The official managed regional federation is a separate service. Self-hosted operators choose their own participants and data policies. Site configuration and managed-service records remain outside this repository.

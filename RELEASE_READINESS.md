# Release readiness and host support

The repository is open source and can be built locally. The packages in this repository are not yet a qualified, signed general release. Do not attach a protected production interface until you have verified a host-specific recovery path.

## Evidence as of 2026-11-18

| Component | Build and test environment | Verified here | Still required for general availability |
| --- | --- | --- | --- |
| Core | Ubuntu 24.04.5, Linux 7.0, AMD64; Go 1.26.10 toolchain | `go test ./...`; AMD64 and ARM64 cross-builds; DEB, RPM and tar package content checks; matching SHA-256 hashes across two builds of all six packages; keyless-attested pilot DEB installed on two clean AMD64 hosts; TEST-mode start, restart, removal and reinstall with local admin token and identity preserved | Prior-version upgrade and rollback; ARM64 runtime; qualified general-release signatures |
| Node agent | Same AMD64 host and Go toolchain | `go test ./...`; two-node private mesh admission over mutual TLS; one-use join-token replay rejected with HTTP 401 | Observation delivery, expiry and revocation tests; clean-host agent recovery |
| Node Guard | Node.js 22 on the same host | 40 tests | Application integration on supported Node.js versions |
| Self-hosted Exchange | Node.js 22, SQLite native module on the same host | Production build; admin, discovery and protocol integration tests | Restore drill and two-host network pilot |
| Firewall Console | Node.js 22 on the same host | 32 tests | Clean-host installation with an agent and recovery drill |

Core requires Linux kernel 5.8 or newer and a mounted BPF filesystem. A successful cross-build does not establish runtime support on another CPU or distribution. We currently have no qualification result for older kernels, other Linux distributions, or Windows hosts. The package pre-install check and manual list additional prerequisites. The two-host pilot kept protected interfaces empty, Exchange sharing off, and enforcement in TEST mode. Its temporary hosts and storage were destroyed after the pilot.

## Release gates

1. Build packages twice from the same source revision and toolchain, then compare SHA-256 hashes for every format. This passed locally on the environment above; repeat it in CI and record the source revision and toolchain versions for a release.
2. Verify package contents contain no private key, cluster identity, live configuration, or operator credentials.
3. Sign the exact release artifacts and publish the signing identity, checksums, and verification instructions. GitHub keyless attestations and a checksum manifest are verified for the pilot candidate; a qualified general release remains to be published.
4. On disposable supported hosts, prove install, TEST-mode start, prior-version upgrade and rollback, uninstall, and data restore. Clean install, restart, and removal/reinstall passed on two Ubuntu 24.04 AMD64 hosts; the other cases remain open.
5. With two noncritical hosts, verify explicit admission, short-lived enrollment, observation delivery, replay resistance, expiry, revocation, source removal, and local enforcement authority. Mutual-TLS admission and replay rejection passed; the remaining behaviors need testing before expanding the network.

The official managed regional federation is a separate service. Self-hosted operators choose their own participants and data policies. Site configuration and managed-service records remain outside this repository.

## Pilot candidate provenance

An operator can trigger the `Attest Core pilot candidate` GitHub Actions workflow on `main`. It builds the packages twice, compares hashes, and creates GitHub keyless provenance attestations for the short-lived workflow artifacts. After downloading and extracting the artifact, run `sha256sum -c SHA256SUMS` from its root and verify each package with `gh attestation verify <package-path> -R Smccann01/HoneyMesh-Open-Source`. Check that the attested source revision and workflow are the ones you intend to test. These artifacts are pilot candidates, not qualified general installers.

The two-host pilot used workflow run `44342252537` from source revision `a5f96dde86255a2df0500e8e10a25593e478b0a0`. The AMD64 DEB checksum and attested subject digest both matched `f929088aa5b21b26179603b8e9b36c025b0a5fe30947985dc899e050965329fe`. The joining host used this exact package. The receiving host used the immediately preceding attested candidate.

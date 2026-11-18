# Release readiness and host support

The repository is open source and can be built locally. The packages in this repository are not yet a qualified, signed general release. Do not attach a protected production interface until you have verified a host-specific recovery path.

## Evidence as of 2026-11-18

| Component | Build and test environment | Verified here | Still required for general availability |
| --- | --- | --- | --- |
| Core | Ubuntu 24.04.5, Linux 7.0, AMD64 and ARM64; Go 1.26.10 toolchain | `go test ./...`; AMD64 and ARM64 cross-builds; DEB, RPM and tar package content checks; matching SHA-256 hashes across two builds of all six packages; keyless-attested pilot DEB installed on two clean AMD64 hosts; TEST-mode start, restart, removal and reinstall with local admin token and identity preserved; one disposable AMD64 host passed an RC2 upgrade, rollback, and local backup restore; one disposable ARM64 host passed install, start, restart, removal, and reinstall with safe defaults and a local admin token | Repeat upgrade and rollback across supported host profiles; validate restored runtime data and behavior; ARM64 detection and enforcement behavior; qualified general-release signatures |
| Node agent | Same AMD64 host and Go toolchain | `go test ./...`; two-node private mesh admission over mutual TLS; one-use join-token replay rejected with HTTP 401; disposable Exchange integration exercises signed observation snapshots, retraction, source revocation, signal expiry, and the receiving Go client | Repeat observation, expiry, revocation, and local enforcement-authority checks on two installed hosts; clean-host agent recovery |
| Node Guard | Node.js 22 on the same host | 40 tests | Application integration on supported Node.js versions |
| Self-hosted Exchange | Node.js 22, SQLite native module on the same host | Production build; admin, discovery and protocol integration tests, including a verified SQLite backup in the disposable discovery suite | Restore drill from backup into a running service and two-host network pilot |
| Firewall Console | Node.js 22 on the same host | 32 tests | Clean-host installation with an agent and recovery drill |

Core requires Linux kernel 5.8 or newer and a mounted BPF filesystem. The ARM64 package has now passed a basic runtime and package recovery check, but detection and enforcement on ARM64 remain unqualified. We currently have no qualification result for older kernels, other Linux distributions, or Windows hosts. The package pre-install check and manual list additional prerequisites. The two-host AMD64 pilot kept protected interfaces empty, Exchange sharing off, and enforcement in TEST mode. Its temporary hosts and storage were destroyed after the pilot.

## Release gates

1. Build packages twice from the same source revision and toolchain, then compare SHA-256 hashes for every format. This passed locally on the environment above; repeat it in CI and record the source revision and toolchain versions for a release.
2. Verify package contents contain no private key, cluster identity, live configuration, or operator credentials.
3. Sign the exact release artifacts and publish the signing identity, checksums, and verification instructions. GitHub keyless attestations and a checksum manifest are verified for the pilot candidate; a qualified general release remains to be published.
4. On disposable supported hosts, prove install, TEST-mode start, prior-version upgrade and rollback, uninstall, and data restore. Clean install, restart, and removal/reinstall passed on two Ubuntu 24.04 AMD64 hosts. One additional Ubuntu 24.04 AMD64 host passed an RC2-to-RC4 upgrade, RC4-to-RC2 rollback, and local configuration backup restore. Repeat across host profiles and verify restored runtime records and application behavior before closing this gate.
5. With two noncritical hosts, verify explicit admission, short-lived enrollment, observation delivery, replay resistance, expiry, revocation, source removal, and local enforcement authority. Mutual-TLS admission and replay rejection passed on two hosts. Signed observations, expiry, revocation, and source removal passed in the disposable Exchange integration suite with a Go receiving client; those behaviors and local enforcement authority still need an installed two-host test before expanding the network.

The official managed regional federation is a separate service. Self-hosted operators choose their own participants and data policies. Site configuration and managed-service records remain outside this repository.

## Pilot candidate provenance

The [public Core pilot pre-release](https://github.com/Smccann01/HoneyMesh-Open-Source/releases/tag/v2.3.6-rc4-pilot.1) provides the installable Ubuntu 24.04 AMD64 DEB and its matching `SHA256SUMS` file. Download both into one directory, run `sha256sum -c SHA256SUMS`, and verify the package with `gh attestation verify honeymesh_2.3.6-rc4-corefirewall4_amd64.deb -R Smccann01/HoneyMesh-Open-Source`. This is a noncritical-host pilot package; the remaining release gates above still apply.

An operator can trigger the `Attest Core pilot candidate` GitHub Actions workflow on `main`. It builds the packages twice, compares hashes, and creates GitHub keyless provenance attestations for the short-lived workflow artifacts. After downloading and extracting the artifact, run `sha256sum -c SHA256SUMS` from its root and verify each package with `gh attestation verify <package-path> -R Smccann01/HoneyMesh-Open-Source`. Check that the attested source revision and workflow are the ones you intend to test. These artifacts are pilot candidates, not qualified general installers.

The two-host pilot used workflow run `44342252537` from source revision `a5f96dde86255a2df0500e8e10a25593e478b0a0`. The AMD64 DEB checksum and attested subject digest both matched `f929088aa5b21b26179603b8e9b36c025b0a5fe30947985dc899e050965329fe`. The joining host used this exact package. The receiving host used the immediately preceding attested candidate.

## One-host upgrade and rollback drill

On 2026-11-18, a disposable Ubuntu 24.04 AMD64 EC2 host with Linux `7.0.0-1017-aws` ran the historical RC2 Debian package (`37aef1515a344f5a2f7cefc993c87b5976eb9da33127ebd22975e6b8f87fc15c`), then upgraded to the free RC4 pilot package (`f929088aa5b21b26179603b8e9b36c025b0a5fe30947985dc899e050965329fe`). Both downloaded files matched those published hashes before installation. The `honeymesh.service` unit was active after each installation. The host then downgraded to RC2 with `apt-get --allow-downgrades`; the service was active again. A local archive of `/etc/honeymesh` and `/var/lib/honeymesh` taken before the upgrade was restored after the rollback; the service started and the configuration file hash matched its pre-upgrade value. The archive and host were destroyed with the temporary test stack.

This was a single-host package and configuration recovery drill. It did not measure detection, network enforcement, restored runtime record contents, longer-term service behavior, or a second host. The old RC2 package was a historical paid pilot artifact; its license behavior is not a requirement of the free RC4 build. The two-host observation, expiry, revocation, and local enforcement-authority gates above remain open.

## ARM64 package runtime drill

On 2026-11-18, a disposable Ubuntu 24.04 ARM64 EC2 host with Linux `7.0.0-1017-aws` installed the ARM64 Debian candidate from attested workflow run `44342252537`, source revision `a5f96dde86255a2df0500e8e10a25593e478b0a0`. Its SHA-256 matched the workflow manifest: `b717fe10b07bc63e7f0d3f0ee9e1f2f6b1369937bc880c2a131d26c1eea6aa2e`. The package installed successfully and `honeymesh.service` was active after installation, restart, and removal followed by reinstall. The host generated a local admin token. Its configuration bound to loopback, selected no protected interfaces, and kept mesh and Exchange sharing off. The temporary host and transfer bucket were destroyed after the drill.

This establishes a basic ARM64 package runtime check, not ARM64 detection or enforcement support. The ARM64 candidate is still a short-lived workflow artifact rather than a published general installer.

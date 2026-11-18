# HoneyMesh 2.0 version line

Status: development only. This branch is the separate HoneyMesh 2.0 source line. The current HoneyMesh Core 2.3.6 RC6 pilot remains on `main` and retains its published package, checksum, and attestation. There is no HoneyMesh 2.0 installer or live enforcement release yet.

## Separation rules

1. Adaptive Trust implementation PRs target `honeymesh-2.0`. Do not merge this branch into `main` as a routine feature update.
2. The existing `honeymesh` DEB/RPM/tar build script refuses to build when the 2.0 development marker is present. The 2.0 branch CI tests source but skips current-line package creation.
3. A 2.0 alpha needs its own package identity, service and state migration design, rollback path, exact artifact attestation, and host qualification before release. It must not impersonate a `2.3.6` artifact or silently downgrade an installed `2.3.6` Core package to a `2.0.x` package.
4. Use a 2.0-specific release tag and channel when those gates pass. Version strings and package names are reserved until the install/upgrade contract is tested. No website download link should point to this branch as an installer.

This separation keeps experimental code reviewable and open source while protecting the existing RC6 pilot channel. The [Adaptive Trust contract](core/docs/ADAPTIVE_TRUST_V1.md) remains observe-only.

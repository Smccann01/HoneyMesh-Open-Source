# HoneyMesh agent for Node integration

This is the verified HoneyMesh 2.3.6-rc2 Iron Hive agent source with the local HoneyMesh Node bridge integrated. The original source archive SHA-256 is `6c020f71f6a54c5566bfd1336d8f04ffc3dcb20e2a9de1a246f513847c245266`. The private `tools/license-keygen` directory was deliberately excluded. The integration and tests are maintained in the parent repository's `agent-integration/` directory.

The baseline rc2 package fixes the federation trust-lock deadlock. Keep license generation in its separate private workflow.

The packaged daemon runs as the dedicated `honeymesh` system user through `systemd`. Linux kernel 5.8 or newer is required for its bounded BPF capabilities. Read [MANUAL.md](MANUAL.md) for installation, migration, service handover, and rollback instructions.

## Build and verify

```sh
go test ./...
go build ./...
```

Use the parent repository's `scripts/build-release.sh` for the HoneyMesh Node release binary and `scripts/exchange-deploy.sh` for the Exchange pilot. See [ARCHITECTURE.md](ARCHITECTURE.md) for the agent architecture.

Production signing keys, credentials, and runtime configuration are not included in this repository.

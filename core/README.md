# HoneyMesh Core

HoneyMesh Core is a defensive agent for supported Linux hosts. Local enforcement and scoped operator grants are available without a purchase or publisher license. TEST is the initial mode. Administrators create credentials locally and explicitly choose protected interfaces, traps, enforcement mode, and any sharing.

Self-hosted Exchange enrollment uses an admin-issued, one-use token. Community intelligence is observation-only by default. Direct mesh requires an operator-configured cluster identity, mutually verified TLS certificates, and explicit opt-in; a receiving node applies its own policy before enforcement.

## Build and verify

```sh
go test ./...
go build ./...
```

Read [MANUAL.md](MANUAL.md), [ARCHITECTURE.md](ARCHITECTURE.md), [LICENSE](LICENSE), and [SECURITY.md](SECURITY.md) before deploying. This is source code, not a signed or qualified production installer. Test on a noncritical host and retain independent recovery access before enabling enforcement.

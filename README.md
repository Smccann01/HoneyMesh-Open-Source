# HoneyMesh open source

HoneyMesh provides defensive tools for existing servers. This public repository contains the Core agent, Node agent and Node Guard SDK, self-hosted Exchange, and Firewall Console source. Network Decode maintains its website and operational records in separate private projects.

| Directory | Component | License |
| --- | --- | --- |
| `core/` | HoneyMesh Core | Apache-2.0 user space; see component license scope for eBPF and documentation |
| `node/` | HoneyMesh Node and Node Guard | Apache-2.0; see component license scope |
| `exchange/` | Self-hosted Exchange | AGPL-3.0-only |
| `firewall-console/` | Local Firewall Console | Apache-2.0 |

Local administrators generate their own credentials. Self-hosted Exchange enrollment uses admin-issued, one-use tokens. Community observations require explicit opt-in, and receiving hosts decide enforcement locally. Direct mesh requires an operator-configured cluster identity and mutual TLS trust.

This is a source preview, not a signed or qualified production installer. Read each component's README, license, and security guidance before deployment. Report vulnerabilities using the component SECURITY.md files.

See [release readiness and host support](RELEASE_READINESS.md) for the tested environment, current limits, and the gates before a signed installer release.

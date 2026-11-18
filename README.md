# HoneyMesh open source

HoneyMesh provides defensive tools for existing servers. This public repository contains the Core agent, Node agent and Node Guard SDK, self-hosted Exchange, and Firewall Console source. Network Decode maintains its website and operational records in separate private projects.

| Directory | Component | License |
| --- | --- | --- |
| `core/` | HoneyMesh Core | Apache-2.0 user space; see component license scope for eBPF and documentation |
| `node/` | HoneyMesh Node and Node Guard | Apache-2.0; see component license scope |
| `exchange/` | Self-hosted Exchange | AGPL-3.0-only |
| `firewall-console/` | Local Firewall Console | Apache-2.0 |

Local administrators generate their own credentials. Self-hosted Exchange enrollment uses admin-issued, one-use tokens. Community observations require explicit opt-in, and receiving hosts decide enforcement locally. Direct mesh requires an operator-configured cluster identity and mutual TLS trust.

The [Core pilot release](https://github.com/Smccann01/HoneyMesh-Open-Source/releases/tag/v2.3.6-rc4-pilot.1) provides a checksummed, keyless-attested AMD64 Debian package for noncritical Ubuntu 24.04 hosts. It is not a qualified general production installer. Start with the [first-server pilot guide](PILOT_QUICKSTART.md), then read the component license and security guidance. Report vulnerabilities using the component SECURITY.md files.

See [release readiness and host support](RELEASE_READINESS.md) for the tested environment, current limits, and the gates before a signed installer release.

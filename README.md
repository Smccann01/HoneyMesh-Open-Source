# HoneyMesh open source

HoneyMesh provides defensive tools for existing servers. This public repository contains the Core agent, Node agent and Node Guard SDK, self-hosted Exchange, and Firewall Console source. Network Decode maintains its website and operational records in separate private projects.

| Directory | Component | License |
| --- | --- | --- |
| `core/` | HoneyMesh Core | Apache-2.0 user space; see component license scope for eBPF and documentation |
| `node/` | HoneyMesh Node and Node Guard | Apache-2.0; see component license scope |
| `exchange/` | Self-hosted Exchange | AGPL-3.0-only |
| `firewall-console/` | Local Firewall Console | Apache-2.0 |

Local administrators generate their own credentials. Self-hosted Exchange enrollment uses admin-issued, one-use tokens. Community observations require explicit opt-in, and receiving hosts decide enforcement locally. Direct mesh requires an operator-configured cluster identity and mutual TLS trust. The official Community Core and Node agent builds support **up to five direct peers per node** (the local node plus five others); the customer-operated Community Exchange remains free and has no Network Decode subscription or five-node limit. This is a feature limit in these builds, not an additional restriction on the open-source licenses or their existing recipients.

## Ubuntu App Center beta

Two separately named HoneyMesh tools are available in the Snap Store beta channel on AMD64:

| Snap | Install | Scope |
| --- | --- | --- |
| [Network Decode Console](https://snapcraft.io/network-decode-console) | `sudo snap install network-decode-console --beta` | Local, observation-only Firewall Console. Requires a separately installed compatible agent for host data and controls. |
| [Node Guard Tools](https://snapcraft.io/network-decode-nodeguard) | `sudo snap install network-decode-nodeguard --beta` | Local policy creation, validation, and simulation. It does not install the Node Guard SDK into an app or protect traffic by itself. |

For Node Guard, run `network-decode-nodeguard init` in a directory under your home folder, then `network-decode-nodeguard doctor nodeguard.policy.json` and `network-decode-nodeguard policy validate nodeguard.policy.json`. Read the [Node Guard Snap guide](node/node-guard/snap/README.md) and the [SDK integration guide](node/node-guard/README.md) before enabling application-level protection. Both Snaps are beta tools; use a noncritical host or application first.

Core and the Node agent are not Snap Store packages yet. Their kernel/XDP access needs an installed-package confinement and recovery test; follow [the agent qualification issue](https://github.com/Smccann01/HoneyMesh-Open-Source/issues/31). Self-hosted Exchange needs a persistent database, private first-run setup, and restore test before Store publication; follow [the Exchange qualification issue](https://github.com/Smccann01/HoneyMesh-Open-Source/issues/32). Do not treat either console Snap as a substitute for the Core or Node agent.

The [Core pilot release](https://github.com/Smccann01/HoneyMesh-Open-Source/releases/tag/v2.3.6-rc4-pilot.1) provides a checksummed, keyless-attested AMD64 Debian package for noncritical Ubuntu 24.04 hosts. It is not a qualified general production installer. Start with the [first-server pilot guide](PILOT_QUICKSTART.md), then read the component license and security guidance. Report vulnerabilities using the component SECURITY.md files.

See [release readiness and host support](RELEASE_READINESS.md) for the tested environment, current limits, and the gates before a signed installer release.

HoneyMesh 2.0 Adaptive Trust is developed separately in a private repository. It is outside this public Snap Store release line. The current open-source pilot release line remains on `main`.

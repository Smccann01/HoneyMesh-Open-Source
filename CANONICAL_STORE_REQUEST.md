# Canonical Snap Store permission requests for Core and Node

**Status:** ready to submit to the [privileged-interfaces category](https://forum.snapcraft.io/c/store-requests/privileged-interfaces/). This file is a submission copy, not evidence of Canonical approval. Post one topic per snap using the text below. Do not publish either agent as host protection until the Store grants a supported permission route and the remaining qualification gates in [issue #31](https://github.com/Smccann01/HoneyMesh-Open-Source/issues/31) pass.

## Topic 1: `network-decode-core` read-only kernel BTF access for an XDP security agent

```yaml
name: network-decode-core
description: Local Linux security agent using eBPF/XDP on an operator-selected network interface
snapcraft: https://github.com/Smccann01/HoneyMesh-Open-Source/blob/main/core/snap/snapcraft.yaml
upstream: https://github.com/Smccann01/HoneyMesh-Open-Source
upstream-relation: The Network Decode publisher maintains the upstream project and this Snap.
plugs:
  kernel-btf:
    interface: system-files
    attributes:
      read: [/sys/kernel/btf/vmlinux]
    request-type: installation
    reasoning: The agent needs read-only kernel BTF to relocate and load its CO-RE eBPF/XDP program. It cannot provide host protection without it. No write access is requested. We also request permission for an operator to connect this plug manually; we do not request auto-connection.
```

Our strict-confinement diagnostic manually connected `network-control`, `mount-observe`, `system-trace`, `firewall-control`, and `kernel-btf` on an isolated Ubuntu 24.04 AMD64 runner. It verified XDP attach, TEST mode, an explicit ENFORCE drop and counter increase, detach, crash/restart and recovery. With only `kernel-btf` disconnected, the agent refused startup and did not attach XDP. Installation does not start the agent or select an interface. Its initial configuration is TEST with sharing disabled.

We know the [published `system-files` policy](https://snapcraft.io/docs/reference/interfaces/system-files-interface/) says non-owned `/sys` paths are outside normal Store acceptance. Is a read-only exception for this single file supportable, or should we use or propose a purpose-specific kernel BTF interface? If neither is available, is classic confinement appropriate for this host security agent? Please advise which of the other manually connected host-control plugs need declarations. We are requesting guidance and installation/manual-connection permission, not auto-connection or a public release today.

Evidence: [passing strict diagnostic with direct BTF load](https://github.com/Smccann01/HoneyMesh-Open-Source/actions/runs/44650128665), [operator guide](https://github.com/Smccann01/HoneyMesh-Open-Source/blob/main/HOST_AGENT_SNAP_PILOT.md), [release gate issue](https://github.com/Smccann01/HoneyMesh-Open-Source/issues/31).

## Topic 2: `network-decode-node` read-only kernel BTF access for an XDP security agent

```yaml
name: network-decode-node
description: Local Linux security agent for Node-related host protection using eBPF/XDP on an operator-selected network interface
snapcraft: https://github.com/Smccann01/HoneyMesh-Open-Source/blob/main/node/agent/snap/snapcraft.yaml
upstream: https://github.com/Smccann01/HoneyMesh-Open-Source
upstream-relation: The Network Decode publisher maintains the upstream project and this Snap.
plugs:
  kernel-btf:
    interface: system-files
    attributes:
      read: [/sys/kernel/btf/vmlinux]
    request-type: installation
    reasoning: The agent needs read-only kernel BTF to relocate and load its CO-RE eBPF/XDP program. It cannot provide host protection without it. No write access is requested. We also request permission for an operator to connect this plug manually; we do not request auto-connection.
```

The Node agent has the same isolated strict-confinement and negative-permission test as Core. Installation does not start the agent or select an interface. Its initial configuration is TEST with sharing disabled. With `kernel-btf` disconnected, it refuses startup and does not attach XDP. We request read-only access to the single `vmlinux` BTF file, or guidance on a purpose-specific interface or classic confinement if `system-files` is unsuitable. The other host-control plugs are manually connected in the diagnostic; please identify any that require declarations. We are not requesting auto-connection or a public release today.

Evidence: [passing strict diagnostic with direct BTF load](https://github.com/Smccann01/HoneyMesh-Open-Source/actions/runs/44650128665), [operator guide](https://github.com/Smccann01/HoneyMesh-Open-Source/blob/main/HOST_AGENT_SNAP_PILOT.md), [release gate issue](https://github.com/Smccann01/HoneyMesh-Open-Source/issues/31).

# Core and Node Snap developer candidates

These packages are **not** in the Ubuntu App Center. They are developer
candidates for the two XDP host agents. The CI builds each Snap, checks its
checksum, installs it in devmode, creates unique local state, verifies that
the Community configuration has no selected interfaces or sharing, and probes
XDP attach/detach on an isolated veth pair. These tests do not establish
production safety or Store readiness.

The separate strict-confinement diagnostic [run 44621989489](https://github.com/Smccann01/HoneyMesh-Open-Source/actions/runs/44621989489)
passed for both agents with `network-control`, `mount-observe`,
`system-trace`, `firewall-control`, and a read-only `system-files` plug for
`/sys/kernel/btf` connected manually. On a veth pair split across network
namespaces, it verified baseline traffic, TEST refusal of a manual ban,
ENFORCE blocking of an exact source, increased XDP drop counters, recovery
after release, return to TEST, and detach on exit. This is a local diagnostic,
not a Store approval or a general production qualification. The BTF plug is
privileged and needs Canonical review before distribution.

Each candidate must be installed with `--devmode --dangerous` from a CI
artifact, on a disposable Ubuntu 24.04 AMD64 host only. Neither package starts
a service on installation. Run `sudo snap run network-decode-core.init` or
`sudo snap run network-decode-node.init` to create private configuration and
certificates under `/var/snap/<snap-name>/common/`. Review the configuration
before running `sudo snap run <snap-name>` manually. Never select a critical
interface for an unqualified test.

Qualification before a Store beta:

1. Extend the isolated veth test to crash, restart, refresh, rollback, and
   uninstall on a disposable host. Record actual kernel and snapd logs.
2. Obtain Store approval for the requested strict interfaces, especially
   read-only kernel BTF. Devmode is diagnostic and is not a release
   confinement model. If strict approval is unavailable, review a classic
   confinement request with Canonical.
3. Prove config, certificates, and runtime state survive refresh; prove
   backup, rollback, and purge behavior. Design an operator-controlled service
   that never attaches a host interface on installation.
4. Test on Ubuntu 24.04 AMD64, including unsupported-kernel and conflicting
   agent cases. Keep the default TEST mode and require local operator action
   before any enforcement.

Track Store readiness in [issue #31](https://github.com/Smccann01/HoneyMesh-Open-Source/issues/31).

## Proposed Store interface review

The publisher is requesting a strict-confinement path for two separate AMD64
Snaps, `network-decode-core` and `network-decode-node`. Both load an eBPF/XDP
program and attach only to an interface explicitly selected by the local
operator. Installation does not start an agent or select an interface. Initial
mode is TEST; sharing is disabled. Local setup generates unique credentials.

The requested non-auto-connected plugs are `network-control` for XDP link
operations, `system-trace` for BPF operations, `mount-observe` for reading
`/proc/self/mountinfo` during BPF initialization, `firewall-control` for
host enforcement, and `kernel-btf` (`system-files`) with read-only access to
`/sys/kernel/btf` for CO-RE relocations. The agent does not need to write to
the BTF directory. The Store team should determine whether the BTF access is
acceptable under strict confinement or whether a dedicated interface is
required. No auto-connection is requested for the privileged plugs in this
pilot.

The [strict probe workflow](.github/workflows/probe-host-agent-strict.yml)
builds temporary strict variants from the developer recipes, manually connects
these plugs, and validates packet-level behavior on an isolated test network.
The developer recipes remain `confinement: devmode` while lifecycle and Store
review gates are open; they must not be uploaded as public protection Snaps.

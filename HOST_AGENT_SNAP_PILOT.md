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
`/sys/kernel/btf/vmlinux` connected manually. On a veth pair split across network
namespaces, it verified baseline traffic, TEST refusal of a manual ban,
ENFORCE blocking of an exact source, increased XDP drop counters, recovery
after release, return to TEST, and detach on exit. This is a local diagnostic,
not a Store approval or a general production qualification. Canonical's current
[system-files interface guidance](https://snapcraft.io/docs/reference/interfaces/system-files-interface/)
says Store acceptance excludes non-owned paths under `/sys`. The diagnostic's
read-only `kernel-btf` plug is therefore not an approved Store design. The
publisher must seek a purpose-specific interface or change BTF loading before
submitting a public revision.

The [BTF permission diagnostic](https://github.com/Smccann01/HoneyMesh-Open-Source/actions/runs/44631434415)
confirmed that this is a runtime dependency for both agents on the tested
Ubuntu runner. With only `kernel-btf` disconnected, each agent failed to load
the CO-RE XDP program and reported that no kernel BTF was found; neither
attached XDP. Reconnecting the plug restored the tested path. The current
strict recipe cannot simply omit that permission.

**Required host capability:** the running kernel must expose readable BTF at
`/sys/kernel/btf/vmlinux`, and a confined Snap must be granted access to it.
Both launchers now check actual readability before starting the agent and
report a specific error if BTF is absent or inaccessible. Setup and package
installation do not start protection. A missing BTF requirement must not be
silently treated as a working host agent.

The [lifecycle CI run](https://github.com/Smccann01/HoneyMesh-Open-Source/actions/runs/44627883020)
passed on disposable Ubuntu 24.04 runners for both agents. The strict diagnostic
verified XDP detach after a forced process exit, restart in TEST with the same
private configuration, key, and admin token; a locally repacked Snap revision
preserved that state through install and revert; purge removed Snap state. The
repacked revision contained the same executable, so this does not qualify an
application-version migration. It also does not cover a real host interface
or Store approval.

The [conflict and snapshot CI run](https://github.com/Smccann01/HoneyMesh-Open-Source/actions/runs/44630382291)
passed for both agents. While an explicitly started service held XDP on an
isolated veth, a second process of the same Snap refused to start without
replacing the first XDP program. After normal Snap removal, reinstall and
snapshot restore recovered the same private configuration, key and admin token;
the service remained disabled and XDP detached. This does not test coexistence
with a separately installed `.deb` agent.

In a disposable Ubuntu 24.04 VM, the released RC6 `.deb` service occupied
`127.0.0.1:9000` and `127.0.0.1:8443`. An explicit start of the earlier Core
Snap candidate then failed on the mesh port and systemd retried it. XDP did
detach after the failed process exited. The updated Core Snap checks the mesh
port before starting the agent and refuses to attach XDP when another service
owns it. Operators must stop and disable `honeymesh.service` before enabling
the Snap; do not leave both services enabled for reboot. This port check is a
startup guard, not proof that two agents can share one protected interface.

The [opt-in service CI run](https://github.com/Smccann01/HoneyMesh-Open-Source/actions/runs/44629269694)
passed for both agents. The separate
[developer-package build](https://github.com/Smccann01/HoneyMesh-Open-Source/actions/runs/44629269782)
confirmed the service is disabled and inactive immediately after installation.
In strict diagnostics, explicit operator start attached XDP only to the
selected isolated veth interface while the agent remained in TEST; stop and
disable detached it again. This is not a test of a real host interface.

Each candidate must be installed with `--devmode --dangerous` from a CI
artifact, on a disposable Ubuntu 24.04 AMD64 host only. Neither package starts
a service on installation. Run `sudo snap run network-decode-core.init` or
`sudo snap run network-decode-node.init` to create private configuration and
certificates under `/var/snap/<snap-name>/common/`. Review the configuration
before starting the service. For an isolated disposable-host test, the operator
can manage the candidate service with the matching name:

```sh
sudo snap services network-decode-core
sudo snap start --enable network-decode-core
sudo snap stop --disable network-decode-core
```

Substitute `network-decode-node` for the Node agent. The service will start on
boot only after `snap start --enable`; use `snap stop --disable` for recovery.
Never select a critical interface for an unqualified test.

Before any strict diagnostic, check the host BTF file with
`test -r /sys/kernel/btf/vmlinux` and manually connect the candidate's
`kernel-btf` plug with `sudo snap connect <snap-name>:kernel-btf`. Check
`snap connections <snap-name>` for that and the other required plugs listed
below. These commands describe a local diagnostic; they do not grant a Store
declaration or make a public install possible. If the service reports that
kernel BTF is unreadable, stop and disable it, confirm the running kernel
provides BTF, and verify the permission connection. Do not bypass the check.

Qualification before a Store beta:

1. Complete a real application-version refresh and test coexistence with an
   installed `.deb` agent on a disposable host. Record kernel and snapd logs
   for failures and recovery.
2. Resolve the `/sys/kernel/btf/vmlinux` Store blocker with Canonical or remove the
   runtime dependency, then obtain approval for the resulting strict interface
   set. Devmode is diagnostic and is not a release confinement model. If strict
   approval is unavailable, review a classic confinement request with Canonical.
3. Qualify the opt-in service on a disposable host across reboot, a real
   application update, rollback, and uninstall, including a failed startup.
4. Test on Ubuntu 24.04 AMD64, including unsupported-kernel and missing
   permission cases. Keep the default TEST mode and require local operator action
   before any enforcement.

Track Store readiness in [issue #31](https://github.com/Smccann01/HoneyMesh-Open-Source/issues/31).
The [Store interface review draft](STORE_INTERFACE_REVIEW_DRAFT.md) contains
the exact question and evidence for Canonical; it has not been submitted.

## Proposed Store interface review

The publisher is requesting a strict-confinement path for two separate AMD64
Snaps, `network-decode-core` and `network-decode-node`. Both load an eBPF/XDP
program and attach only to an interface explicitly selected by the local
operator. Installation does not start an agent or select an interface. Initial
mode is TEST; sharing is disabled. Local setup generates unique credentials.

The diagnostic's non-auto-connected plugs are `network-control` for XDP link
operations, `system-trace` for BPF operations, `mount-observe` for reading
`/proc/self/mountinfo` during BPF initialization, `firewall-control` for
host enforcement, and `kernel-btf` (`system-files`) with read-only access to
`/sys/kernel/btf/vmlinux` for CO-RE relocations. The agent does not need to write to
the BTF directory, but current `system-files` Store policy excludes non-owned
`/sys` paths. Ask the Store and snapd teams whether a purpose-specific BTF
interface exists or can be added, or whether a different BTF loading design is
required. No auto-connection is requested for the privileged plugs in this
pilot.

The [strict probe workflow](.github/workflows/probe-host-agent-strict.yml)
builds temporary strict variants from the developer recipes, manually connects
these plugs, and validates packet-level behavior on an isolated test network.
The developer recipes remain `confinement: devmode` while lifecycle and Store
review gates are open; they must not be uploaded as public protection Snaps.

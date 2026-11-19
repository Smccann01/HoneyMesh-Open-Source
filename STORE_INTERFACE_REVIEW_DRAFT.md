# Draft: Snap Store interface guidance for HoneyMesh Core and Node

**Status:** draft for Canonical review, not submitted and not a Store approval.
Do not upload or release the current developer Snaps as public protection
packages while this question and the remaining lifecycle gates are open.

## Proposed request

**Title:** Guidance for HoneyMesh XDP agents that read kernel BTF under strict confinement

**Snaps:** `network-decode-core` and `network-decode-node`, separately reserved
under the Network Decode publisher account. Both are AMD64 Ubuntu 24.04
developer candidates. Neither has a released Store revision.

HoneyMesh Core and Node are local host security agents. They load eBPF/XDP
programs and attach to a network interface only after an operator explicitly
selects that interface. First-run configuration selects no interface, starts in
TEST, and disables sharing. Installation does not start a service. Setup
generates per-host certificates and an admin token in the Snap's private common
data. The agents use no hosted account for local operation.

Our isolated Ubuntu 24.04 strict-confinement test manually connected
`network-control`, `mount-observe`, `system-trace`, `firewall-control`, and a
read-only `kernel-btf` plug (`system-files: read: [/sys/kernel/btf]`). Both
agents attached XDP to a disposable veth interface, refused a ban in TEST,
blocked one synthetic source in ENFORCE, incremented XDP drop counters,
released the source, returned to TEST, and detached on exit. A separate
lifecycle test killed the process, verified detach, restarted with the same
private state, installed a locally repacked revision with the same executable,
reverted it, and purged the Snap. These are local diagnostics, not a tested
application-version migration, Store review, or production qualification.

The current [system-files interface documentation](https://snapcraft.io/docs/reference/interfaces/system-files-interface/)
says Store acceptance excludes non-owned `/sys` paths. The kernel BTF files
are needed for the current CO-RE loader, but HoneyMesh does not own them. We
are **not** asking for an exception through `system-files` without guidance.

**Questions for the Store and snapd teams:**

1. Is there a purpose-specific strict interface that permits read-only kernel
   BTF access for an eBPF/XDP agent? If not, should one be proposed?
2. Is a different BTF loading method expected for a distributable strict Snap?
3. Which of `network-control`, `mount-observe`, `system-trace`, and
   `firewall-control` require declarations or additional review for these two
   reserved names? We are not requesting auto-connection in the pilot.
4. If no strict-confinement route is supportable, would a classic-confinement
   request be appropriate for a host security agent with an operator-selected
   interface and no install-time enforcement?

**Evidence:**

- [Snap recipes and operator boundary](https://github.com/Smccann01/HoneyMesh-Open-Source/blob/main/HOST_AGENT_SNAP_PILOT.md)
- [Strict packet-level test](https://github.com/Smccann01/HoneyMesh-Open-Source/actions/runs/44621989489)
- [Crash, restart, local revision revert, and purge test](https://github.com/Smccann01/HoneyMesh-Open-Source/actions/runs/44627883020)
- [Release gate issue](https://github.com/Smccann01/HoneyMesh-Open-Source/issues/31)

We will keep the Snaps in developer testing until the Store permission route,
refresh/revert behavior, conflict handling, and operator recovery have been
qualified. We can provide the exact denial logs and a minimal reproducer to
reviewers without posting host credentials or private keys.

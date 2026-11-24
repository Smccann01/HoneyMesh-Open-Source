# Linux host qualification matrix

The website's Linux selector is a discovery catalog. A distribution row becomes a tested HoneyMesh profile only after an exact product release and package pass a host test with recorded kernel, architecture, interface, attachment mode, and recovery result. A newer kernel alone does not qualify a host.

## Automated first batch

The `Qualify published host DEBs on Ubuntu VMs` workflow runs six combinations: Core RC7 and Node Pro RC2 on GitHub-hosted Ubuntu 22.04, 24.04, and 26.04 AMD64 virtual machines. It downloads each **published** DEB and checksum manifest, verifies the release attestation, installs the package, and records the actual `uname -r`. These standard runners are separate VMs and [free for public repositories](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).

The active test refuses an existing HoneyMesh installation and requires an explicit disposable-host marker. It uses a private veth and network namespace, not the VM's management interface. Each job checks:

1. Package installation, service startup, safe defaults, and TEST mode.
2. Baseline reachability from a test source and separate control source.
3. Generic XDP attachment to the isolated veth.
4. Rejection of a manual block in TEST.
5. One exact-source block in ENFORCE, a rising XDP drop counter, and continued reachability from the control source.
6. Release of the block, return to TEST, XDP detach, and preservation of local identity across a service restart.

Every job uploads a JSON report containing the product tag, package SHA-256, actual OS/kernel/architecture, checks, and failure reason. It never uploads the administrator token, node key, or local configuration. A passing job is a **scoped VM pilot result**, not a native-NIC, throughput, long-running reliability, or production certification. Node Pro's application bridge is outside this first packet-path test.

The same isolated host probe also passed a [Debian 12 and 13 AWS VM batch](results/2026-11-24-debian-aws.md) for the two published host packages. Those results are tied to the pinned AMIs and exact cloud kernels in that record.

For a read-only inventory on any Linux host:

```bash
python3 .github/scripts/qualify-host-deb.py --inventory-only
```

## Remaining distribution and product work

The public Core RC7 and Node Pro RC2 releases currently provide AMD64 DEBs. This first batch can test the existing download on Ubuntu; it cannot qualify an RPM distribution, ARM64 installation, or the private HoneyMesh 2.0 package from those assets.

For Debian, RHEL-family, Amazon Linux, SUSE, and other Linux entries, boot a vendor-published, pinned VM image for each OS version and architecture. Use a short-lived test instance with no inbound management port, Systems Manager access, an encrypted root volume, IMDSv2, a fixed termination deadline, and an exact package or source revision. Record AMI ID and owner as well as the kernel and NIC driver. [Systems Manager Run Command](https://docs.aws.amazon.com/systems-manager/latest/userguide/run-command.html) can run the same probe and collect its report without SSH. Estimate and approve the instance and image cost before launching a paid matrix.

Run the stages separately:

| Stage | What it establishes |
| --- | --- |
| Package and runtime | Exact artifact installs, starts in TEST, keeps identity, and can be removed or rolled back. |
| Generic XDP | Isolated veth attach, selected-source drop, control-source pass, counters, release, and detach. |
| Native XDP | Driver-specific attach and packet behavior on qualified NIC hardware. |
| Product integrations | Node Pro app bridge, Firewall Console paired with the exact Core release, private Exchange, and commercial 2.0 licensing in their separate workflows. |
| Performance | Packet rate, latency, CPU, and loss on a dedicated generator and device under test. |

The private HoneyMesh 2.0 package must remain in a private test pipeline. Node Guard is an application SDK and needs a Node.js/runtime matrix, not an XDP kernel matrix. The self-hosted Exchange needs a Node.js/SQLite, TLS, backup, and network matrix. A single private Exchange test does not qualify the hosted service.

Do not automatically update the Network Decode compatibility registry from CI. Review every report against the exact release, host, package format, and tested behavior first; retain failures and missing test coverage as distinct states.

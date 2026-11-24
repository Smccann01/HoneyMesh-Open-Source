# Debian 12 and 13 host qualification — 2026-11-24

Four fresh, disposable EC2 `t3.small` AMD64 VMs ran the same isolated host probe used in the Ubuntu matrix. Each VM used a Debian Cloud Team AMI owned by `136693071363`, an encrypted 8 GiB gp3 root volume, standard CPU-credit mode, IMDSv2, and a security group with no inbound rules. Systems Manager ran the probe; the test role had only `AmazonSSMManagedInstanceCore`. The instances, root volumes, security group, instance profile, and role were removed after report collection.

| Published package | Debian AMI | Kernel observed | Result |
| --- | --- | --- | --- |
| Core RC7 `v2.3.6-rc7-community5-pilot.1` | Debian 12 `ami-081b3ab523443bed5` (`debian-12-amd64-20261117-2665`) | `6.1.0-56-cloud-amd64` | 13/13 passed |
| Node Pro RC2 `node-pro-v2.3.7-rc2-community5-pilot.1` | Debian 12 `ami-081b3ab523443bed5` (`debian-12-amd64-20261117-2665`) | `6.1.0-56-cloud-amd64` | 13/13 passed |
| Core RC7 `v2.3.6-rc7-community5-pilot.1` | Debian 13 `ami-01757311770dc7690` (`debian-13-amd64-20261123-2671`) | `6.12.118+deb13-cloud-amd64` | 13/13 passed |
| Node Pro RC2 `node-pro-v2.3.7-rc2-community5-pilot.1` | Debian 13 `ami-01757311770dc7690` (`debian-13-amd64-20261123-2671`) | `6.12.118+deb13-cloud-amd64` | 13/13 passed |

Core RC7 package SHA-256: `2048b703266378c61ba604ed654777e6789e10450e1c1da70025deb27b12ce3d`. Node Pro RC2 package SHA-256: `89d7a4a9f8c48223a86e01e5684b5e15d3e7cc2cc57b94ff13e51d5d72c69388`. The probe script was pinned to merged commit `244cc06c5bd45c4fc2584c999bd09b0a7ffd54cc` and verified against SHA-256 `295a7271d8be9a09ed9f2b8d569977acff597eb1fd12c0accfd363a4e7572464` before execution.

All four reports recorded BPF filesystem mounted and kernel BTF present. Every case passed package installation, service start, safe defaults, TEST mode, baseline traffic, generic XDP attachment on an isolated veth, TEST refusal of a manual block, exact-source blocking in ENFORCE, control-source pass, increasing XDP drop count, release restoring traffic, return to TEST, and local identity preservation with XDP detach after restart.

The published probe at the pinned commit labels disposable VMs as "GitHub-hosted" in its limitations string; this batch ran on AWS EC2. That generic wording is corrected in the probe after this run without changing test behavior. These results establish a **scoped VM pilot** on the exact AMIs and kernels shown. They do not establish native NIC behavior, packet-rate performance, Node Pro application-bridge behavior, long-running reliability, production readiness, or support for every Debian installation.

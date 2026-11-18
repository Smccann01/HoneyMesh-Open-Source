# First server: HoneyMesh Core pilot

This guide is for a **noncritical Ubuntu 24.04 AMD64 host** with provider-console recovery access. The current package is a pilot candidate; [release readiness](RELEASE_READINESS.md) lists what remains before general production use. Keep your existing protections in place while you evaluate it. **Use RC6 or newer for trusted-network sharing. RC4 has a confirmed peer-revocation defect.**

## 1. Check the host and recovery route

From the host, record these results in your own change record:

```bash
cat /etc/os-release
uname -m
uname -r
findmnt /sys/fs/bpf
ip -br link
```

Proceed only with Ubuntu 24.04, `x86_64`, a kernel at least 5.8, and a mounted BPF filesystem. Confirm that a provider console or separate management route works. Record the current firewall and interface configuration. Do not select a protected interface during installation.

## 2. Download and verify the exact pilot

Download the AMD64 `.deb` and `SHA256SUMS` from [v2.3.6-rc6-pilot.1](https://github.com/Smccann01/HoneyMesh-Open-Source/releases/tag/v2.3.6-rc6-pilot.1) into the same directory. Then run:

```bash
sha256sum -c SHA256SUMS
gh attestation verify honeymesh_2.3.6-rc6-corefirewall4_amd64.deb \
  -R Smccann01/HoneyMesh-Open-Source
```

The expected SHA-256 is `fc3699945f5ea2904bffa22dd8ff5bbc074ba7b4fc9a3e8b9245c8ffd748dbf6`. Stop if the checksum or attestation fails. A current GitHub CLI (`gh`) with `gh attestation` support is needed for the attestation check; inspect the verified source revision and workflow before installation.

## 3. Install without sharing or enforcement

```bash
sudo dpkg -i ./honeymesh_2.3.6-rc6-corefirewall4_amd64.deb
systemctl is-active honeymesh.service
sudo python3 - <<'PY'
import json
config = json.load(open('/etc/honeymesh/honeymesh.json'))
assert config['bind_ip'] == '127.0.0.1'
assert config['interfaces'] == []
assert not config['trusted_mesh_network_enabled']
assert not config['trusted_network_sharing_enabled']
print('Safe pilot defaults confirmed')
PY
```

The first start generates a unique local administrator token in `/var/lib/honeymesh/runtime-state.json`. Read it as root **on that host** when you need dashboard access; keep it out of tickets, logs, screenshots, and chat. The installer also generates a local TLS identity. Do not copy another node's token, state, or private key into this installation.

## 4. Observe, then decide whether to expand

Keep TEST mode and no protected interface for the first check. Review service health and local events. If you plan to attach an interface, establish the rollback path and a separate control route first; follow the [operator manual](node/agent/MANUAL.md) for TLS and mesh settings. Exchange and direct mesh sharing require separate, explicit opt-in and trusted peers. A peer's observation must not be treated as an unrestricted firewall command.

## 5. Stop or recover

To stop the pilot service without removing state:

```bash
sudo systemctl stop honeymesh.service
```

To remove the package while retaining local configuration and state:

```bash
sudo dpkg -r honeymesh
```

Before any upgrade, back up `/etc/honeymesh` and `/var/lib/honeymesh` to a private location and test restoring them on a noncritical host. The [operator manual](node/agent/MANUAL.md) describes the full removal path. Do not delete those directories until you have decided the local identity and records are no longer needed.

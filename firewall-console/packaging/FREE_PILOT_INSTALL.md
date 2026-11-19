# Firewall Console beta.9 free pilot

This bundle installs the local Firewall Console in **read-only host mode by default** on one noncritical Ubuntu 24.04 AMD64 host. It requires a separately installed, matching HoneyMesh Core RC6 pilot agent, Node.js 20 or newer at `/usr/bin/node`, npm, and HTTPS access to the npm registry for pinned dependencies. It does not enroll a managed Exchange account. Keep an independent provider-console recovery route.

Download this bundle and its `SHA256SUMS` from the same release. Verify both the checksum and the public GitHub artifact attestation before extracting:

```sh
sha256sum -c SHA256SUMS
gh attestation verify network-decode-firewall-console-0.2.1-beta.9-free-pilot.tar.gz -R Smccann01/HoneyMesh-Open-Source
mkdir firewall-pilot
tar -xzf network-decode-firewall-console-0.2.1-beta.9-free-pilot.tar.gz -C firewall-pilot
```

Install and start the [Core RC6 pilot](https://github.com/Smccann01/HoneyMesh-Open-Source/releases/tag/v2.3.6-rc6-pilot.1) first. Keep it in TEST with no protected interface. Confirm the agent's local certificate exists at `/etc/honeymesh/certs/node/node.crt` and its loopback health endpoint responds. Then install this console:

```sh
sudo sh firewall-pilot/network-decode-firewall-console-0.2.1-beta.9/install-console.sh firewall-pilot/network-decode-firewall-console-0.2.1-beta.9
sudo systemctl is-active network-decode-firewall.service
curl --fail http://127.0.0.1:8787/health
```

Open the UI through a local browser or an SSH tunnel to `127.0.0.1:8787`. The console creates a one-time bootstrap token locally; retrieve it on the host using the command printed by the installer. Create an admin account and keep the token private. The installed service sets `HM_HOST_ACTIONS_ENABLED=0`; no host block is available until an operator explicitly enables the scoped-action path.

## Optional scoped controls on a disposable host

Core RC6 and this Console passed one disposable Ubuntu 24.04 AMD64 host test: the Console rejected a block in TEST; after an operator attached a generic XDP interface and entered ENFORCE, a single exact-source, 60-second grant reconciled to the kernel, scoped release reconciled, and the Console returned the host to TEST. XDP was detached afterward. This proves the control and recovery API path for that host. Packet-drop behavior under live traffic, broad false-positive rates, and production operation remain unqualified.

For a **noncritical host with a tested provider-console recovery path**, first create the local Console admin account, save the HoneyMesh operator token in Console Settings, and confirm Core remains in TEST. Then opt in from this verified bundle directory:

```sh
sudo sh firewall-pilot/network-decode-firewall-console-0.2.1-beta.9/enable-host-actions.sh 'ENABLE SCOPED HOST ACTIONS'
```

Enabling the switch does not leave TEST or attach an interface. Confirm the intended interface and a controlled source before deliberately entering ENFORCE. The Console only permits bounded exact-source operator grants and release of its own grant ID. Stop if the agent contract, local account, or TEST-mode precondition fails. To disable new Console writes:

```sh
sudo sh firewall-pilot/network-decode-firewall-console-0.2.1-beta.9/disable-host-actions.sh
```

Disabling Console writes does not release an existing HoneyMesh grant. Release the grant or return the host to TEST before removing the Console.

To remove the console while preserving its local account state and leaving Core intact:

```sh
sudo sh firewall-pilot/network-decode-firewall-console-0.2.1-beta.9/uninstall-console.sh firewall-pilot/network-decode-firewall-console-0.2.1-beta.9
```

Do not use the historical paid `CUSTOMER_INSTALL.md` with this free pilot bundle.

# Firewall Console beta.9 free read-only pilot

This bundle installs the local Firewall Console in **read-only host mode** on one noncritical Ubuntu 24.04 AMD64 host. It requires a separately installed, matching HoneyMesh Core RC6 pilot agent, Node.js 20 or newer at `/usr/bin/node`, npm, and HTTPS access to the npm registry for pinned dependencies. It does not enable host-write actions, XDP enforcement, or a managed Exchange account. Keep an independent provider-console recovery route.

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

Open the UI through a local browser or an SSH tunnel to `127.0.0.1:8787`. The console creates a one-time bootstrap token locally; retrieve it on the host using the command printed by the installer. Create an admin account and keep the token private. The installed service sets `HM_HOST_ACTIONS_ENABLED=0`, and this free bundle does not include the host-action enable script. Core RC6 contains the scoped-grant API, but an installed-host console control and recovery pilot is still required before that path can be offered publicly. No host block is available from this bundle.

To remove the console while preserving its local account state and leaving Core intact:

```sh
sudo sh firewall-pilot/network-decode-firewall-console-0.2.1-beta.9/uninstall-console.sh firewall-pilot/network-decode-firewall-console-0.2.1-beta.9
```

Do not use the historical paid `CUSTOMER_INSTALL.md` with this free pilot bundle.

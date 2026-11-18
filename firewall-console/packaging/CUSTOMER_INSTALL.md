# Network Decode Firewall Beta: customer host setup

This private console is available with a standalone Firewall subscription and included with a paid Node Pro or Infrastructure Pro host subscription. Use one paid host license per Linux host. The console starts on loopback with host writes disabled. It is an exact-source ingress control candidate, not a full replacement for a host firewall.

## 1. Verify the bundle

Use the publisher public key and full fingerprint provided on the paid download page. Compare the downloaded archive SHA-256 with the pinned website hash. Import the key into a new GPG home and verify the detached manifest signature before extracting or installing anything. Stop if the fingerprint, signature, package hash, or plan does not match. Do not use a manifest or hash from a different release.

## 2. Check the host

Use a noncritical Ubuntu 24.04 AMD64 host with a separate provider console and an existing rollback path. Install Node.js 20 or newer at `/usr/bin/node`, npm, `jq`, and the signed host agent package for your paid plan. The Core and Node Pro Debian packages have the same package identity: install the one matching your subscription, not both. Start HoneyMesh in TEST and confirm `sudo systemctl status honeymesh.service --no-pager` and `curl --cacert /etc/honeymesh/certs/ca/ca.crt https://127.0.0.1:8443/api/health`.

## 3. Install the emailed license for this host

Keep each license JSON outside the web root and assign one distinct file to each purchased host. Inspect its `tier` and `cluster_id` for standalone Firewall (`FIREWALL`) or Infrastructure Pro (`PRO`), or `product` and `unit_id` for Node Pro. Stop if the document is for another plan or host. Never copy a signing key or license generator to the customer host.

For **standalone Firewall** and **Infrastructure Pro**, on a fresh agent installation only, copy the emailed host document to the agent's private state directory and restart. The standalone document must say `"tier": "FIREWALL"`; Infrastructure Pro must say `"tier": "PRO"`. A Firewall license permits local enforcement but does not enable trusted mesh or network sharing. If `cluster.id` or `license.json` already exists, stop and use the bundled `CUSTOMER_UPDATE.md` under support supervision so the existing registration is preserved.

```sh
sudo test ! -e /var/lib/honeymesh/cluster.id
sudo test ! -e /var/lib/honeymesh/license.json
sudo install -o honeymesh -g honeymesh -m 0600 /path/to/emailed-host-license.json /var/lib/honeymesh/license.json
sudo systemctl restart honeymesh.service
sudo systemctl is-active --quiet honeymesh.service
```

For **Node Pro**, the emailed document has `product: node_pro`. Use the matching `NODE_PRO_APP_BRIDGE.md` for application registration. Install the document in `/etc/honeymesh/node-pro-entitlement.json`, owned by `honeymesh:honeymesh` and mode `0600`. If that destination already exists, preserve the current registration and follow the renewal procedure instead.

```sh
sudo test ! -e /etc/honeymesh/node-pro-entitlement.json
sudo install -o honeymesh -g honeymesh -m 0600 /path/to/emailed-node-pro-license.json /etc/honeymesh/node-pro-entitlement.json
sudo jq -r '.product, .unit_id, .expires_at' /etc/honeymesh/node-pro-entitlement.json
sudo install -d -o root -g root -m 0755 /etc/systemd/system/honeymesh.service.d
sudoedit /etc/systemd/system/honeymesh.service.d/10-node-pro-license.conf
```

Add these lines in the editor, replacing `YOUR_UNIT_ID` with the exact `unit_id` just printed:

```ini
[Service]
Environment=HM_NODE_PRO_ENTITLEMENT_FILE=/etc/honeymesh/node-pro-entitlement.json
Environment=HM_NODE_PRO_UNIT_ID=YOUR_UNIT_ID
```

Save the file, then run `sudo chmod 0644 /etc/systemd/system/honeymesh.service.d/10-node-pro-license.conf && sudo systemctl daemon-reload && sudo systemctl restart honeymesh.service`. Confirm agent health and paid host status before enabling application or host enforcement. The signed Node Pro customer archive must include the bridge tarball and provisioner named in `NODE_PRO_APP_BRIDGE.md` before publication; beta.8 test archives do not.

At renewal, replace only this host's document with the newly emailed signed document, preserving permissions, then restart and recheck the paid contract. An expired or missing entitlement must prevent new host grants. Keep the old document in a protected backup until the replacement is confirmed.

## 4. Install the local console

From the verified, extracted bundle directory, run `sudo sh ./install-console.sh .`. The script creates a dedicated `networkdecode` service user, installs root-owned program files under `/opt/network-decode-firewall/releases/0.2.1-beta.9`, and stores private local credentials under `/var/lib/network-decode-firewall`. It pins the agent's local TLS leaf certificate and starts the console on `127.0.0.1:8787`. The installer does not enable host-write actions or change HoneyMesh to ENFORCE.

Run `sudo systemctl status network-decode-firewall.service --no-pager`. On a remote VPS, run `ssh -L 8787:127.0.0.1:8787 USER@HOST` from your laptop and open `http://127.0.0.1:8787` locally. For first account setup, read the one-time bootstrap token on the host:

```sh
sudo -u networkdecode node -p 'require("/var/lib/network-decode-firewall/credentials.json").adminToken'
```

Paste it into **Create admin account** and set a unique password of at least 16 characters. The bootstrap token cannot sign in after the account is created. Keep it out of chat, tickets, screenshots, and shell history.

## 5. Connect HoneyMesh

The HoneyMesh operator token is separate from the console bootstrap token, local password, and paid license. Read it on the host with `sudo jq -r '.admin_token' /var/lib/honeymesh/runtime-state.json`, then enter it once in **Settings → HoneyMesh operator access**. The root config can have an empty admin token because the generated active token is saved in private runtime state. The console encrypts the saved token and verifies the local TLS pin before sending it to the agent.

Confirm that Overview shows the correct agent mode and that Interfaces lists the intended host interface. Keep the agent in TEST while you check normal traffic, management access, and a controlled source/control pair. New scoped host-write actions remain disabled until the following reviewed enablement step. The paid host contract and local admin account must be ready. From the verified bundle directory, run:

```sh
sudo sh ./enable-host-actions.sh 'ENABLE SCOPED HOST ACTIONS'
```

This enables the console's scoped-action API but leaves HoneyMesh in TEST. Recheck management access and the intended XDP interface before an administrator deliberately enters ENFORCE in the HoneyMesh SOC. The Firewall console then permits temporary exact-source blocks for at most 24 hours and release of its own grant ID. It cannot terminate a socket or create a permanent ban. To close the console write path again, run `sudo sh ./disable-host-actions.sh` from the same verified bundle. Closing that path does not remove active HoneyMesh grants; release them through the agent or SOC first.

## 6. Recovery and removal

If the console fails, run `sudo systemctl disable --now network-decode-firewall.service`. This stops the console without changing HoneyMesh rules. To remove this exact console release, first run `sudo sh ./disable-host-actions.sh` if enabled, then `sudo sh ./uninstall-console.sh .` from its verified bundle directory. Removal stops the console and deletes its installed program and service, while preserving HoneyMesh and the private account state at `/var/lib/network-decode-firewall`. Reinstall or update requires the signed bundle and `CUSTOMER_UPDATE.md`. Removing private account state permanently requires a separate deliberate purge.

If network access is affected, use the provider console to return HoneyMesh to TEST or stop `honeymesh.service`; detach the selected XDP interface using the version-matched HoneyMesh recovery guide.

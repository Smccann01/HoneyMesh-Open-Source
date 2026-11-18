# Node Pro application bridge: paid host beta

This guide belongs to the **Node Pro** paid host archive. The archive includes the matching Node Pro agent, the local Firewall console, `honeymesh-node-guard-0.1.2.tgz`, and `provision-node-pro.py`. The bridge package is a compatibility component for the Node Pro agent. It is separate from the public Node Guard Free SDK and needs a paid Node Pro host entitlement for host enforcement.

Use a noncritical Ubuntu 24.04 AMD64 host. Start with one application in TEST and a provider console for recovery. Complete the parent `CUSTOMER_INSTALL.md` first, including signature checks, the emailed Node Pro entitlement, and agent health. Each protected app needs its own Linux UID and a new registration. Do not reuse another app's secret, socket, or unit ID.

## Register an application

Find the Linux user that runs the app and its numeric UID. Replace `APP_USER`, `APP_UID`, and `billing_api_01` in the commands. The app ID must use only letters, digits, underscores, or hyphens.

```sh
id APP_USER
sudo python3 ./provision-node-pro.py --app-id billing_api_01 --app-uid APP_UID --output /root/node-pro-review
sudo cat /root/node-pro-review/node-edge-apps.json
```

Review the UID, socket path, `auto_block: false`, and empty `canary_ips`. Stop if this host already has `/etc/honeymesh/node-edge-apps.json` or the chosen app ID; merge with the existing registration under an administrator's review instead of replacing it.

```sh
sudo install -d -o honeymesh -g honeymesh -m 0700 /etc/honeymesh/apps
sudo install -o honeymesh -g honeymesh -m 0600 /root/node-pro-review/agent-secret /etc/honeymesh/apps/billing_api_01.secret
sudo install -o honeymesh -g honeymesh -m 0600 /root/node-pro-review/node-edge-apps.json /etc/honeymesh/node-edge-apps.json
sudo install -d -o root -g root -m 0755 /etc/systemd/system/honeymesh.service.d
sudo install -o root -g root -m 0644 /root/node-pro-review/20-node-pro.conf /etc/systemd/system/honeymesh.service.d/20-node-pro.conf
```

The Node Pro entitlement and its exact `unit_id` must already be configured in the agent's systemd drop-in as described in `CUSTOMER_INSTALL.md`. Preserve both that configuration and the new app registration in one reviewed drop-in set. Do not create two conflicting values for `HM_NODE_PRO_UNIT_ID`.

Give only `APP_USER` access to the client copy of the secret and to the agent socket's `honeymesh` group. The app must restart after group membership changes. Never put a secret into a command line argument, chat, source repository, or browser page.

```sh
sudo install -d -o APP_USER -g APP_USER -m 0700 /var/lib/billing-api/node-pro
sudo install -o APP_USER -g APP_USER -m 0600 /root/node-pro-review/client-secret /var/lib/billing-api/node-pro/client-secret
sudo usermod -aG honeymesh APP_USER
sudo systemctl daemon-reload
sudo systemctl restart honeymesh.service
sudo systemctl is-active --quiet honeymesh.service
```

Install the bundled bridge package in the application project with `npm install /path/to/honeymesh-node-guard-0.1.2.tgz`. Configure the bridge with the reviewed `appId`, socket path, and the private client secret read from its file. The app must send only events derived from its own trusted request context. In TEST, confirm one controlled event is recorded as `observed` and no XDP grant is created. Check that a different UID, app ID, or secret is rejected. Then restart both agent and app and repeat the checks.

Do not enable `auto_block` during initial setup. A later ENFORCE test needs a controlled source, an independent control source, protected management addresses, a short TTL, and a proven recovery path. The local Firewall console's host-write buttons stay disabled until the administrator completes the reviewed enablement step in `CUSTOMER_INSTALL.md`.

For rollback, stop the bridge client, return the agent to TEST, remove only this app's registration and secret after preserving a protected backup, reload systemd, and restart the agent. Keep the paid entitlement for other apps on the same purchased host. For a renewal, replace the Node Pro entitlement with the new signed JSON for the **same unit ID**, restart, and confirm the contract before re-enabling enforcement.

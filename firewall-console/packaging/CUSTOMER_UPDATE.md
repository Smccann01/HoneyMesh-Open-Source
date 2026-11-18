# HoneyMesh paid host beta: supported update and rollback

This guide is for a **support-assisted beta update** on one noncritical Ubuntu 24.04 AMD64 host. It applies to the plan-matched standalone Firewall, Infrastructure Pro, or Node Pro host bundle. Keep the old, verified bundle and a provider console available throughout. The console installer deliberately refuses to replace an existing release in place.

## Before changing anything

1. Verify the new archive against the SHA-256 and full publisher fingerprint on the paid download page. In a fresh GPG home, verify the embedded public key fingerprint, detached manifest signature, plan, and every artifact hash. Keep the old signed bundle for rollback. Never use a test-only archive as a customer update.
2. Record the current agent and console versions, the host license identity (`cluster_id` or Node Pro `unit_id`), the selected interface, and the active grants. Use the HoneyMesh SOC to release temporary grants and return the agent to **TEST**. Check that the provider console and management connection still work.
3. Preserve the current host identity, license, Node Pro app registration, and console account state in a root-only backup. The backup contains credentials; keep it outside the web root, Git, and shared folders.

```sh
sudo install -d -o root -g root -m 0700 /root/honeymesh-update-backup
sudo sh -c 'set -eu; umask 077; set -- etc/honeymesh var/lib/honeymesh var/lib/network-decode-firewall; if test -d /etc/systemd/system/honeymesh.service.d; then set -- "$@" etc/systemd/system/honeymesh.service.d; fi; tar -C / -czf /root/honeymesh-update-backup/pre-update-state.tar.gz "$@" 2>/root/honeymesh-update-backup/tar-errors.txt'
sudo test -s /root/honeymesh-update-backup/pre-update-state.tar.gz
sudo systemctl is-active --quiet honeymesh.service
```

Read `tar-errors.txt`; stop if any required path was absent or unreadable. Record the backup checksum in your private change ticket. Do not send the backup to support unless a separately approved secure transfer is arranged.

## Install the reviewed update

Run the first two commands from the **old verified bundle**, then the remaining commands from the **new verified bundle**. Keep the old bundle and backup intact.

```sh
sudo sh ./disable-host-actions.sh
sudo sh ./uninstall-console.sh .
```

Choose **one** plan-matched agent command from the new bundle:

Standalone Firewall or Infrastructure Pro (Core bundle):

```sh
sudo dpkg -i ./honeymesh_2.3.6-rc4-corefirewall7_amd64.deb
```

Node Pro:

```sh
sudo dpkg -i ./honeymesh_2.3.6-rc4-nodepro7_amd64.deb
```

Then run:

```sh
sudo systemctl is-active --quiet honeymesh.service
sudo sh ./install-console.sh .
sudo systemctl is-active --quiet network-decode-firewall.service
```

Use the exact package filename from the new signed manifest if a later release changes it. If `dpkg` asks about an existing `/etc/honeymesh/honeymesh.json`, preserve the current configuration and stop for review if the new release requires a schema migration. Do not run the **fresh-host** license-copy commands over an existing `cluster.id`, `license.json`, or Node Pro entitlement.

Verify the same paid license identity, expected applications, TEST mode, interface state, console login, saved operator access, and management connectivity. A new node TLS leaf may require the console's pin to refresh; the installer writes the current local leaf fingerprint. Confirm the console still starts with host writes disabled. Only after a controlled source/control test may an administrator run the new bundle's `enable-host-actions.sh` and deliberately re-enter ENFORCE.

## Rollback

Return the agent to TEST and confirm management access. Run `disable-host-actions.sh` and `uninstall-console.sh` from the **new** bundle. From the **old verified** bundle, reinstall its plan-matched Debian package and console using the same commands above. Recheck the paid license, app registrations, console account, management access, and TEST mode before any enforcement.

If the agent changed its persistent-state schema, stop and use a support-assisted restore from the root-only backup. Do not overwrite active state directories blindly. If management access is lost, use the provider console and the version-matched HoneyMesh emergency recovery procedure. Keep the agent in TEST until the cause is understood.

This guide covers a controlled, same-host beta update. Compatibility with future state-schema changes must be validated for each release before that release is offered as an update.

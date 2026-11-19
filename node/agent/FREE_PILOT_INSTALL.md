# Node Pro free pilot installation

This package is a **noncritical Ubuntu 24.04 AMD64 pilot**. It upgrades the `honeymesh` host agent to `2.3.7-rc1-nodepro1` and adds the multi-app Node.js bridge. It does not require a commercial Node Pro license. Start in TEST mode with no protected interfaces and `auto_block: false` for every application. Do not enable host blocks until the installed-host canary and recovery tests for your host pass.

Download the AMD64 `.deb` and `SHA256SUMS` from the same release. Check both the package hash and its GitHub keyless provenance before installing:

```sh
sha256sum -c SHA256SUMS
gh attestation verify honeymesh_2.3.7-rc1-nodepro1_amd64.deb -R Smccann01/HoneyMesh-Open-Source
```

Keep provider-console access and a copy of the previous Core RC6 package. Back up `/etc/honeymesh` and `/var/lib/honeymesh` privately before upgrading. The archive includes local certificates and administrator credentials; keep it readable only by root.

```sh
sudo tar -C / -czf /root/honeymesh-before-node-pro.tgz etc/honeymesh var/lib/honeymesh
sudo chmod 0600 /root/honeymesh-before-node-pro.tgz
sudo dpkg -i ./honeymesh_2.3.7-rc1-nodepro1_amd64.deb
sudo systemctl is-active honeymesh.service
sudo dpkg-query -W -f='${Version}\n' honeymesh
sudo python3 -c 'import json; d=json.load(open("/etc/honeymesh/honeymesh.json")); assert d["interfaces"] == [] and not d["trusted_network_sharing_enabled"]; print("Safe pilot defaults present")'
```

The agent generates its administrator token locally. The package does not contain a shared token or private key. Add one or two apps only after following [the multi-app identity and socket guide](NODE_EDGE_MULTI_APP.md). Each app needs its own Linux UID, socket, and secret. The host agent must see the app's actual UID on the Unix socket; container UID mappings require a separate check.

Rollback requires a maintenance window. Return to TEST, stop the agent, reinstall the exact previous Core package with `sudo dpkg -i --force-downgrade ./honeymesh_2.3.6-rc6-corefirewall4_amd64.deb`, then restart and inspect the service. Restore the private backup only if the configuration or state migration needs recovery. Test this route on a disposable host before relying on it.

This package is not a general production release. The free app bridge provides local observation in TEST; kernel actions require local ENFORCE mode, an attached eligible interface, `auto_block: true`, an exact canary source, verified app identity, and a short grant TTL. No peer or Exchange participant gains authority over local app grants.

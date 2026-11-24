# Node Pro free pilot installation

This package is a **noncritical Ubuntu 24.04 AMD64 proof-of-concept pilot**. It upgrades the `honeymesh` host agent to `2.3.7-rc3-community5` and includes the multi-app Node.js bridge. The official Community build allows up to five direct mesh peers per node; a customer-operated Community Exchange remains independent of that limit. Use the pilot to test host fit before deciding whether to purchase the separate private HoneyMesh 2.0 package. The open-source license still governs source use and modification. Start in TEST mode with no protected interfaces and `auto_block: false` for every application. Do not enable host blocks until the installed-host canary and recovery tests for your host pass.

Download the AMD64 `.deb` and `SHA256SUMS` from the same release. Check both the package hash and its GitHub keyless provenance before installing:

```sh
sha256sum -c SHA256SUMS
gh attestation verify honeymesh_2.3.7-rc3-community5_amd64.deb \
  -R Smccann01/HoneyMesh-Open-Source \
  --signer-workflow Smccann01/HoneyMesh-Open-Source/.github/workflows/attest-node-pro-pilot.yml \
  --source-digest 6e84eb27d49876f2d405c1a6996173220e1b366e
```

Keep provider-console access and a copy of the exact package currently installed, such as Core RC8 or Node Pro RC2. Back up `/etc/honeymesh` and `/var/lib/honeymesh` privately before upgrading. The archive includes local certificates and administrator credentials; keep it readable only by root.

```sh
sudo tar -C / -czf /root/honeymesh-before-node-pro.tgz etc/honeymesh var/lib/honeymesh
sudo chmod 0600 /root/honeymesh-before-node-pro.tgz
sudo dpkg -i ./honeymesh_2.3.7-rc3-community5_amd64.deb
sudo systemctl is-active honeymesh.service
sudo dpkg-query -W -f='${Version}\n' honeymesh
sudo python3 -c 'import json; d=json.load(open("/etc/honeymesh/honeymesh.json")); assert d["interfaces"] == [] and not d["trusted_network_sharing_enabled"]; print("Safe pilot defaults present")'
```

The agent generates its administrator token locally. The package does not contain a shared token or private key. Add one or two apps only after following [the multi-app identity and socket guide](NODE_EDGE_MULTI_APP.md). Each app needs its own Linux UID, socket, and secret. The host agent must see the app's actual UID on the Unix socket; container UID mappings require a separate check.

Rollback requires a maintenance window. Return to TEST, stop the agent, reinstall the exact previous package with `sudo dpkg -i --force-downgrade ./<previous-honeymesh-package>.deb`, then restart and inspect the service. Restore the private backup only if the configuration or state migration needs recovery. Test this route on a disposable host before relying on it.

This package is not a general production release. The free app bridge provides local observation in TEST; kernel actions require local ENFORCE mode, an attached eligible interface, `auto_block: true`, an exact canary source, verified app identity, and a short grant TTL. No peer or Exchange participant gains authority over local app grants.

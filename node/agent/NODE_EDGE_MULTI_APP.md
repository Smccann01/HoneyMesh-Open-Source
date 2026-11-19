# Candidate multi-app Node bridge

This is a free Node Pro pilot feature. Begin with two apps in TEST mode and `auto_block: false`. App-initiated kernel enforcement remains unqualified until the installed-host canary and rollback gates pass.

Set `HM_EDGE_APPS_FILE` in the HoneyMesh agent service to an absolute path to a protected JSON file. Do not set `HM_EDGE_SOCKET` at the same time. The config and secret files must be regular files owned by root or the agent UID, readable by the agent, with no group write or world access. Symlinked files are rejected. Protect their parent directories as well. Each app needs a different Unix UID, socket path, and secret of at least 32 bytes. Provision at most 16 apps.

```json
{
  "apps": [
    {
      "app_id": "payments_api_01",
      "source": "node_guard",
      "socket": "/run/honeymesh/payments.sock",
      "secret_file": "/etc/honeymesh/apps/payments.secret",
      "uid": 1001,
      "auto_block": false,
      "canary_ips": ""
    },
    {
      "app_id": "catalog_api_02",
      "source": "node_guard",
      "socket": "/run/honeymesh/catalog.sock",
      "secret_file": "/etc/honeymesh/apps/catalog.secret",
      "uid": 1002,
      "auto_block": false,
      "canary_ips": ""
    }
  ]
}
```

The agent creates each socket with mode `0660`. Set the parent directory and groups so the intended app process can connect. The bridge also checks the kernel-provided peer UID and the signed `app_id` in every event. It rejects a wrong UID, secret, app ID, or generic source. The active-block snapshot is scoped to the registered app ID. The Node client sends `app_id` when `createAgentBridge({ socketPath, secret, appId })` is configured; the reference service reads `HM_EDGE_APP_ID`.

For containers or user namespaces, configure the UID as the agent sees it on the Unix socket, then verify that value in the two-process pilot.

`auto_block` remains off by default. Enabling it requires exact `canary_ips`, ENFORCE mode, an attached eligible interface, and the agent's existing source policy. App events are kept local and do not enter Exchange publication. Audit rows include the app ID. One app cannot take over an already active ban on the same source IP; such an event remains observed.

The free multi-app path does not require a commercial entitlement. Local safeguards still govern every app grant: a registered app identity, matching Unix peer UID and secret, an exact canary source, an attached eligible interface, ENFORCE mode, and a bounded TTL. Start with `auto_block: false` and no protected interface while validating evidence. The earlier single-socket Exchange integration is unaffected.

Before release, run two different Linux UIDs and real Node services on one clean VM. Verify positive events for each app, cross-socket access, wrong secret, wrong UID, wrong claimed app ID, per-app snapshots, restart, expiry, and manual rollback. A unit test or one-process socket test does not close that gate.

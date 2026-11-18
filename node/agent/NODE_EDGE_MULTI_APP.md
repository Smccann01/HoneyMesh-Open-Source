# Candidate multi-app Node bridge

This is an RC4 development-branch feature. A two-app TEST-mode pilot passed on a disposable Ubuntu VM; customer ENFORCE and the signed Node Pro package remain unqualified. Keep the existing single-socket deployment until the release gates are complete.

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

Multi-app enforcement also requires `HM_NODE_PRO_ENTITLEMENT_FILE` to point to a protected, publisher-signed Node Pro host entitlement and `HM_NODE_PRO_UNIT_ID` to match its `unit_id`. The agent reads and verifies the entitlement immediately before each app grant. Missing, expired, modified, wrong-plan, wrong-unit, symlinked, or writable files leave events in observe state with audit detail `entitlement_inactive`. The earlier single-socket Exchange integration is unaffected. Existing short-lived app grants retain their own bounded TTL if the entitlement expires after a grant was made; new grants stop. The host unit is a licensed assignment and not a hardware fingerprint. These settings are for the next signed Node Pro package; the older unsigned candidate does not contain this check.

Before release, run two different Linux UIDs and real Node services on one clean VM. Verify positive events for each app, cross-socket access, wrong secret, wrong UID, wrong claimed app ID, per-app snapshots, restart, expiry, and manual rollback. A unit test or one-process socket test does not close that gate.

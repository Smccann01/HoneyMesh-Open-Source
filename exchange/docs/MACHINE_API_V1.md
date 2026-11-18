# HoneyMesh Exchange machine API v1

This is the self-hosted machine API contract. It is not permission to enable distributed blocking. Configure agents with the TLS-verified origin of your own Exchange installation.

## Enrollment and authorization

`POST /api/hm/bootstrap` accepts a verified paid `PRO` license claim plus a separately publisher-signed, unexpired `exchange_mesh_trial` entitlement for the same cluster. The entitlement cannot outlive the paid license. Enrollment creates a node secret once; repeating an ID or machine fingerprint returns `409 node_limit_or_identity_conflict` and never returns the old secret. The licensed node limit is checked inside the registration write transaction. Sharing starts disabled, review-only mode enabled, and automatic approval disabled. Trial issuance is an operator action on the private license service, not a public API.
The original release signer and the current HM-Keygen signer are trusted for paid-license verification. The license and trial entitlement must verify under the same signer; mixing signatures from two trusted keys is rejected. This matches the HoneyMesh agent's trusted publisher set.

Subsequent machine requests require `x-hm-node-id`, `x-hm-timestamp`, `x-hm-nonce`, `x-hm-body-sha256`, and `x-hm-signature`. The HMAC-SHA256 request signature covers method, encoded path plus query, timestamp, nonce, and raw body separated by newlines. Requests older or newer than five minutes, reused nonces, mismatched body hashes, inactive nodes, and invalid signatures are rejected. Machine responses carry `x-hm-response-timestamp`, `x-hm-response-body-sha256`, and `x-hm-response-signature`; recipients must verify them before acting. Discovery mutations and audit reads also require an Ed25519 node identity signature. See [Discovery protocol](../DISCOVERY_PROTOCOL_V1.md).

The Exchange TypeScript and HoneyMesh Node Go implementations share a fixed nonproduction HMAC test vector. Run `npm run test:protocol` in this repository and `go test . -run TestExchangeProtocolV1CrossLanguageVector` in the Node agent module before changing signature canonicalization.
For an optional disposable cross-runtime HTTP check, build Exchange and run `HM_GO_AGENT_DIR=/absolute/path/to/HoneyMesh-Node/agent npm run test:discovery`. The suite starts a temporary Exchange server, enrolls test identities in its isolated database, and invokes the actual Go client before and after retraction. It removes the temporary server and database afterward.

## Routes used by nodes

| Route | Purpose |
|---|---|
| `POST /api/hm/heartbeat` | Report node liveness; does not change sharing or trust |
| `GET /api/hm/config` | Read tenant sharing, kill switch, review and policy state |
| `POST /api/hm/publish-ban` | Submit a bounded, attributable signal for review or delivery |
| `GET /api/hm/attack-feed` | Page approved signals and retractions with independent cursors |
| `GET /api/hm/attack-snapshot` | Obtain one complete active ownership view and retraction cursor |
| `POST /api/hm/ban-feedback` | Record recipient decision feedback |

The feed accepts `trustThreshold` 0–100, `limit` 1–250, `after` as the opaque signal cursor, and `retractionAfter` as a nonnegative integer cursor. Invalid numeric inputs return a signed 400. Snapshot accepts `trustThreshold` 0–100. A snapshot above 2,500 records returns signed `409 snapshot_too_large` with no usable records. Agents must not advance either cursor or replace local ownership after an incomplete or invalid snapshot.
Feed and snapshot records carry the remaining signal TTL as of delivery. A late first delivery cannot restart the original TTL on a receiving node.

An authenticated node may report `offline` and later recover with a signed `online` heartbeat. While offline, its other machine routes remain unavailable. A revoked node cannot use the recovery heartbeat.

`GET /api/hm/discovery/*` provides optional, hidden-by-default cluster discovery and relationship review. Directory approval never joins a direct mesh or authorizes local XDP enforcement. Each recipient still needs an explicitly trusted source, active scoped entitlement, an unexpired signal, local allowlist checks, ENFORCE mode, and automatic enforcement enabled.

## Retraction and recovery

Each retraction identifies the original signal ID, source cluster, attacker IP, sequence, and retraction time. The recipient removes only that signal's UEE grant and preserves other local, application, trusted-mesh, and Exchange grants for the same IP. Retractions are retained for seven days. On startup, after an outage, or before ENFORCE pulls, the agent reconciles a complete signed snapshot; it must release stale owners and apply only eligible current owners. If the snapshot fails, leave existing bounded rules to their TTL and keep cursors unchanged. See [RC4 retraction contract](../RC4_RETRACTION_CONTRACT.md).

## Qualification boundary

Local tests cover the contract, signed discovery, tenant separation, replay rejection, snapshot size, and ownership logic. General Pro release additionally requires exact-build two-node IPv4/IPv6 packet tests, retraction under traffic, outage/restart recovery, four-owner removal orders, backup restore, false-positive and performance limits, and a monitored pilot. Track those results in [API-HoneyMesh execution](../API_HONEYMESH_EXECUTION_2026-11-05.md).

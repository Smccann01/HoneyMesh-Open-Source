# HoneyMesh enforcement decision API candidate

These routes are a source-level candidate. They are not in the currently installed signed agent. All three require the existing `X-Honey-Token` operator credential on the local HoneyMesh HTTPS API. The preview route also uses the existing Origin and JSON-body checks. Responses are `no-store`.

| Route | Purpose |
| --- | --- |
| `GET /api/enforcement/decision?ip=<exact-ip>` | Current UEE grant owners, last reported kernel state, override, mode, and XDP attachment for one address. |
| `POST /api/enforcement/preview` | Read-only scope and readiness preview for `{ "ip": "8.8.8.8", "ttl_seconds": 300 }`. |
| `GET /api/enforcement/history?ip=<exact-ip>&limit=25` | Newest persisted UEE reconciliation records for one address; limit 1–100. |

The decision outcome is one of `kernel_block_reported`, `release_override_active`, `grant_pending_or_not_applied`, or `no_active_uee_grant`. A reported kernel block is the UEE's last confirmed map state, not proof that a particular packet was dropped. The response includes each active grant's owner, reason, policy version, and expiry. A missing grant does not mean every other firewall path accepted the address.

The preview never creates a grant, changes host mode, or runs a packet simulation. It lists blockers such as TEST mode, protected source, absent paid entitlement, no attached XDP interface, or an active release override. `immediate_kernel_effect_possible` is only a readiness indication; a later write still needs its own authorization and reconciliation. The scope is **inbound exact-source traffic across applications and ports on attached interfaces**, not one selected socket.

The history route reads the UEE's existing SQLite reconciliation journal. It records apply/remove attempts, the owner set, policy versions, result, retry status, and any kernel error. It is not packet capture, a complete operator activity log, or proof of traffic direction. History is newest-first and bounded per request. The journal has no retention policy yet, so storage retention and export need separate design before describing it as a long-term flight recorder.

Keep the operator token out of URLs, logs, browser JavaScript, and support messages. The existing scoped write routes remain the only path to create or release an operator grant; these new reads do not expand write authority.

# Adaptive Trust v1 contract and threat model

Status: source-level, observe-only prototype. No runtime calls this evaluator and it grants no live network or application access. The production policy, identity adapter, storage, and enforcement point are future work.

## Scope

`internal/adaptivetrust` evaluates one exact `(tenant_id, subject_id, resource_id, action, session_id)` request. The first intended pilot is one authenticated web service calling one API read route. A management route and admin action are negative controls. HoneyMesh Core's IP enforcement engine cannot enforce a user role or one API action; a future resource-side adapter must enforce those decisions.

This contract is independent of direct-mesh Behavioral Trust Levels. A peer's score or a remote Exchange report is evidence at most. Neither is an explicit HAT grant. Existing BTL behavior is unchanged by this prototype.

## Input authority

| Input | Required authority | Untrusted cases to reject before evaluation |
| --- | --- | --- |
| Request | Protected resource or authenticated local bridge | Client-selected tenant, resource, action, or session without server binding |
| Identity | Credential verifier at the resource boundary | IP address alone, unsigned claim, wrong session, expired certificate or token |
| Grant | Authorized local operator or designated identity system | Score-derived grant, expired approval, cross-tenant grant, unapproved action |
| Posture | Independent local verifier | Peer assertion alone, stale evidence, issuer not permitted by local policy |
| Anomaly | Independent local verifier | Forged, stale, cross-relationship, or correlated duplicate reports |
| Hold | Durable local authority | Remote quarantine command, timer-only release, unapproved removal |
| Policy | Versioned local configuration | Unknown version, missing maximum lease, wider scope than the approved grant |

Adapters must authenticate and authorize issuers before setting `Verified` on identity or evidence. The pure evaluator cannot verify cryptographic signatures or prove that an adapter is honest. A future call site must not accept arbitrary JSON from a network peer as one of these trusted Go values.

## Decision order

1. Reject malformed request, schema, clock, or policy.
2. Enforce an exact durable hold before considering a grant. Holds do not expire automatically.
3. Require a current operator-approved grant for the exact tenant, subject, resource, action, and policy version.
4. Require a verified identity bound to the exact session.
5. Restrict a verified current anomaly for the exact relationship.
6. Require fresh independent posture when the policy says so.
7. Return `allow` only for the preapproved action, with a lease bounded by policy, grant, identity, and posture expiry.

`verify` and `restrict` are **non-permitting** results in this version. A later adapter may implement a challenge or lower-rate path, but must not treat either result as an allow. A stored `allow` is usable only before `lease_until`; it must also remain bound to the original session, resource, action, and policy version when an adapter is implemented.

The decision contains a schema version, state, effect, reason code, grant ID, accepted evidence IDs, policy version, evaluation time, and optional lease expiry. The evaluator does not persist this record or claim that an enforcement point applied it.

## Illustrative input

The Go API uses `time.Time` values and a `time.Duration` maximum lease. The following is an example for fixture authors, not a network endpoint:

```json
{
  "schema_version": 1,
  "request": {"tenant_id":"tenant-a","subject_id":"web-a","resource_id":"api-orders","action":"orders.read","session_id":"session-1"},
  "identity": {"subject_id":"web-a","session_id":"session-1","verifier_id":"pilot-ca","verified":true,"expires_at":"2027-01-01T00:01:00Z"},
  "grant": {"id":"grant-1","tenant_id":"tenant-a","subject_id":"web-a","resource_id":"api-orders","actions":["orders.read"],"approved_by":"operator-1","issued_at":"2026-12-31T23:59:00Z","expires_at":"2027-01-01T01:00:00Z","policy_version":"pilot-1"},
  "posture": {"id":"posture-1","subject_id":"web-a","verifier_id":"posture-checker","verified":true,"observed_at":"2026-12-31T23:59:59Z","expires_at":"2027-01-01T00:00:45Z"}
}
```

At `2027-01-01T00:00:00Z`, a local policy with version `pilot-1`, required posture, and a 30-second maximum lease can return an `allow` until `00:00:30Z`. Changing the action to `admin.write`, removing the grant, or using another tenant returns `deny` regardless of otherwise healthy evidence.

## Threats and required later checks

- **Stolen valid credential:** identity verification alone must not grant an unapproved resource or action. Test the management route and admin action as negative controls.
- **Forged identity or evidence:** adapters must verify the issuer, credential, trust chain, audience, subject, session binding, freshness, and replay state. This package receives only the validated result.
- **Benign-history gaming:** there is no trust score in the authorization path. Repeated normal events cannot add grant actions.
- **Malicious peer collusion:** correlated reports from one authority cannot count as independent proof. Correlation and provenance checks belong in a later evidence adapter.
- **Quarantine bypass:** a verified compromise must create a durable local hold before access resumes; the pure evaluator rejects an active hold at any age. Hold placement, persistence, and authorized release are not yet implemented.
- **Decision replay:** a future transport must bind a decision to the same tenant, subject, session, resource, action, policy version, and unexpired lease.
- **Store or service outage:** future callers must deny new privileged sessions and honor only a specifically bounded low-risk lease. This package has no store or outage handling.
- **Enforcement mismatch:** the resource must report what it actually applied. This package does not claim a packet drop, HTTP denial, or revoked database role.

## Test boundary

`go test ./internal/adaptivetrust` covers no-grant and no-escalation decisions, session/tenant/resource mismatch, stale identity and posture, verified anomaly, durable hold behavior, and the shortest lease boundary. `go test -race ./internal/adaptivetrust` checks the current pure package. These are source-level tests, not two-host or production qualification.

The local simulator reads synthetic fixtures and labels output as a simulation:

```sh
cd core
go run ./tools/hat-sim -at 2030-01-01T00:00:00Z < docs/fixtures/hat-read-allow.json
go run ./tools/hat-sim -at 2030-01-01T00:00:00Z < docs/fixtures/hat-admin-deny.json
```

The simulator does not read the local HAT store, verify signatures, issue grants, or enforce its result. Fixture `verified` flags model an upstream verifier and are not proof of one.

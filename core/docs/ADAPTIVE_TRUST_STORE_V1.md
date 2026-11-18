# Adaptive Trust local state v1

Status: source-level store candidate. No runtime code opens it or acts on its records. It uses the caller's SQLite connection and creates namespaced `hat_*` tables, leaving existing enforcement tables unchanged.

The store accepts only authenticated caller decisions. Its methods do **not** verify an operator, certificate, signed observation, or independent posture check. The future Core adapter must perform those checks before writing a grant, hold, revocation, or release.

## Durable records

- Grants are insert-only by ID. An identical retry is idempotent. Widening actions under an existing ID is rejected; replacing a grant requires a new authorized ID. Querying an active grant is scoped to tenant, subject, resource, action, policy version, issuance time, expiry, and revocation state.
- Holds are exact to tenant, subject, resource, and action. An active hold has no timer. It survives restart until a separate authorized approver supplies an independent verification reference and releases it. The database permits only one active hold for a relationship/action.
- Decision audit is append-only and queryable only with an exact relationship and a bounded limit. It records a decision, not proof of applied enforcement.

The source-level `Preview` service discards any caller-supplied grant or hold and loads those from the local store. It returns a non-permitting result on a storage or audit error. The identity and posture inputs still require a trusted adapter; `Preview` has no HTTP route and is not a live permission service.

Schema version is stored in `hat_meta`; unknown versions stop store initialization. SQLite errors and corrupt grant JSON return errors. A future decision service must convert such errors to a non-permitting result; it must never treat missing or unreadable storage as an allow.

## Integration gate

Before any runtime use, implement an authenticated operator write API, source-verified evidence ingestion, a read-only evaluation/preview service, audit retention policy, and backup/restore tests. Keep the existing Core TEST default. The store does not authorize a network block, user role, API route, or Exchange command.

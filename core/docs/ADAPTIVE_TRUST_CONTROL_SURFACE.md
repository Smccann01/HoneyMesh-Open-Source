# HoneyMesh 2.0 Adaptive Trust preview console

Status: observe-only development surface on the `honeymesh-2.0` branch. Core initializes the namespaced local HAT store after the existing UEE starts. Store failure makes the HAT panel unavailable without changing existing Core enforcement. No HAT grant or hold writer, identity adapter, application enforcement route, or kernel quarantine runtime call is exposed here.

The Core SOC Console has an **Adaptive Trust 2.0** preview panel. It inspects one exact tenant, subject, resource, action, and policy version. It shows the matching active local grant, local hold, bounded decision audit, and latest preview. The browser renders returned values as text, not HTML. The panel labels identity verification and enforcement as unavailable or disabled.

All endpoints require the existing local admin token and return `Cache-Control: no-store` on success:

| Endpoint | Purpose |
| --- | --- |
| `GET /api/adaptive-trust/status` | Report preview availability and disabled enforcement paths. |
| `GET /api/adaptive-trust/relationship` | Return the exact active grant, hold, and up to 25 recent decisions for the requested relationship. Requires `tenant_id`, `subject_id`, `resource_id`, `action`, and `policy_version`; optional `limit` defaults to 10. |
| `POST /api/adaptive-trust/preview` | Evaluate the exact relationship using only durable local grant and hold state. Requires the five identifiers as JSON; checks Origin and limits the body to 4 KiB. It writes a decision audit record. |

The preview endpoint supplies **no identity or posture assertion**. A browser cannot set `verified=true` or fabricate evidence. With an active grant but no verified identity, its expected result is `verify`; with a local hold, `deny/quarantined`; without a grant, `deny`. An `allow` from this unauthenticated-evidence preview is treated as an error. No endpoint changes a grant, a hold, traffic, Core mode, or the XDP map.

Next gates: authenticate operator grant and hold writes, bind a real workload identity and posture verifier to the protected session, add exact-route observe-only decisions, and define retention and immediate release before exposing enforcement controls. The kernel bridge remains separately disabled.

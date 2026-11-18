# HoneyMesh Node Guard development candidate

This is a private, framework-neutral Node.js application limiter and a separately imported local agent client. It does not attach eBPF/XDP, parse HTTP headers, or publish bans to the Exchange. The Guard keeps state in one process, so restart clears active limits. Do not publish it as a production package yet.

For a repeatable internal package and clean-app check, follow the [developer setup](DEVELOPER_SETUP.md).

The `0.2.0-alpha.6` development source adds an optional host bridge adapter to license-free, in-process application protection. The free protection itself does not create host-level grants or require a HoneyMesh agent. The package remains private while deployment-specific validation, install guidance, and customer migration are built and tested. The previously distributed `0.1.2` pilot bundle is unchanged.

```js
import { createNodeGuard } from "@honeymesh/node-guard";

const guard = createNodeGuard({
  mode: "observe", // Explicitly switch to enforce after source and allowlist review.
  canActOnSource: (verifiedClientIp) => !operatorAddresses.has(verifiedClientIp),
});

// The application supplies evidence and a verified client address.
guard.record({ sourceIp: verifiedClientIp, reasonCode: "invalid_signature_burst" });
if (guard.isBlocked(verifiedClientIp)) return tooManyRequests();
```

The example names `operatorAddresses`, `verifiedClientIp`, and `tooManyRequests` are application-provided values or functions. No package code reads `X-Forwarded-For` or infers a trusted address automatically. In enforce mode, `canActOnSource` is required. The library rejects nonpublic addresses and bounds state and restriction duration.

### Express adapter in this development candidate

`@honeymesh/node-guard/express` supplies middleware for an existing Guard instance. It checks active application restrictions and sends HTTP 429 with `Retry-After`; your application still records actual security evidence with `guard.record(...)`. The adapter does not classify arbitrary requests as attacks.

```js
import { createNodeGuard } from "@honeymesh/node-guard";
import { createExpressNodeGuard } from "@honeymesh/node-guard/express";

const guard = createNodeGuard({
  mode: "observe",
  canActOnSource: (sourceIp) => !operatorAddresses.has(sourceIp),
});

// Use only when the application receives connections directly. If a proxy is
// present, resolve the source through a separately verified trusted-ingress rule.
app.use(createExpressNodeGuard({
  guard,
  getVerifiedSourceIp: (req) => req.socket.remoteAddress,
}));
```

If trusted ingress cannot provide a source, the middleware forwards an error to Express rather than silently bypassing enforcement. Configure an error handler and verify direct versus proxied deployment before enabling `enforce`. The in-process state is per worker and clears on restart.

### Trusted proxy source attribution

`@honeymesh/node-guard/trusted-source` provides an exact-peer resolver for direct connections and explicitly named proxies:

```js
import { createTrustedSourceResolver } from "@honeymesh/node-guard/trusted-source";

const resolveSource = createTrustedSourceResolver({
  trustedProxyIps: ["127.0.0.1"], // Example for a local test proxy only.
});
app.use("/login", createExpressNodeGuard({ guard, getVerifiedSourceIp: resolveSource }));
```

Set `trustedProxyIps` to the actual immediate and upstream proxy addresses. The proxy must append or replace `X-Forwarded-For` with the peer it really observed. The resolver ignores forwarding headers from untrusted peers, walks the trusted chain from right to left, and rejects a missing or malformed header from a trusted proxy. It supports exact IP addresses only in this candidate; CIDR ranges and dynamic cloud load balancer peers require a separately qualified ingress adapter. The resolver establishes source attribution; application policy still decides whether that source is eligible for restriction.

### Versioned policy tools

The v1 policy and observation validator and **pure simulator** are available through `@honeymesh/node-guard/policy` and the CLI. The simulator does not install live restrictions. The separate `@honeymesh/node-guard/policy-runtime` export applies one validated policy in one application process. Its v1 scope is source IP within one application and one exact route ID; subject, tenant, and API-key scopes are deferred until their trust contracts are implemented.

```sh
nodeguard init
nodeguard doctor nodeguard.policy.json
nodeguard policy validate examples/auth-policy.json
nodeguard policy test examples/auth-policy.json examples/auth-observations.json --at 2026-11-03T18:00:00Z
```

`init` creates `nodeguard.policy.json` in OBSERVE mode and refuses to overwrite an existing file. `doctor` checks the local Node.js version and optional policy syntax, but cannot verify trusted source attribution or application integration. `OBSERVE` produces a simulated observation decision with no restriction expiry. To simulate `ENFORCE`, change the example policy's mode in a local copy and rerun the command. The examples use a public address only as synthetic input; the CLI sends no packets.

For a route-specific application integration, create a `createPolicyGuardV1` instance from a validated policy and mount `createExpressNodeGuard` only on the matching Express route. The application must generate unique event IDs and call `guard.record(observation)` only after it has observed the stated behavior. The runtime rejects mismatched application IDs, route IDs, and reason codes; stale and duplicate event IDs do not increase the count. It uses bounded memory and temporary local restrictions. `DENY` returns 403 and `THROTTLE` returns 429 through the Express adapter.

The v1 runtime is in-process only. It does not share counters across workers, preserve restrictions across restart, automatically classify requests, or qualify Node Pro host-level action. The trusted-source resolver must be configured for the actual ingress before use. `createHoneyMeshGuard` remains the compatibility API for the existing signed paid pilot.

### Next.js App Router candidate

`@honeymesh/node-guard/next-route` checks a Web `Request` in a Route Handler and returns a `Response` for an active restriction or `null` to continue. It requires `getVerifiedSourceIp`; a missing or failed source callback returns 503. It does not read forwarding headers itself. See the [Next Route Handler guide](NEXT_ROUTE_GUIDE.md) for its exact support boundary. A direct single-process Node.js deployment is the intended evaluation target; Edge, serverless process churn, and multi-replica state consistency are not qualified.

The existing `createHoneyMeshGuard` pilot API now permits free application ENFORCE mode. It still requires an explicit verified-source policy and retains bounded thresholds, durations, and capacity. Existing `entitlement` and `unitId` options are accepted for compatibility but are not required. Host-level actions through the agent bridge require a configured local app identity, authenticated requests, an explicit agent ENFORCE mode, and source policy.

Pass a **verified** client address from a trusted ingress. Never pass a client-supplied `X-Forwarded-For` value. In `enforce` mode, provide `canActOnSource` to exclude operators, monitors, trusted proxies, and other local policy exceptions. Private, loopback, link-local, and multicast addresses are rejected by the library.

```js
import { createHoneyMeshGuard } from "@honeymesh/node-guard";

const operatorAddresses = new Set(); // Populate from your trusted operator policy.
const auditDecision = (decision) => console.info(decision);
// verifiedClientIp must come from your trusted ingress integration.
const guard = createHoneyMeshGuard({
  mode: "observe", // Switch to enforce only after attribution and allowlist tests.
  // entitlement: customerEntitlement, unitId: customerEntitlement.unit_id,
  canActOnSource: (verifiedClientIp) => !operatorAddresses.has(verifiedClientIp),
  onDecision: (decision) => auditDecision(decision),
});

// Call this only for a real application signal, such as a failed HMAC signature.
guard.record({ sourceIp: verifiedClientIp, reasonCode: "invalid_signature_burst", protocol: "HTTPS" });

// In enforce mode, check before costly application work and return HTTP 429 if true.
if (guard.isBlocked(verifiedClientIp)) return tooManyRequests();
```

This package deliberately does not decide whether a request is malicious. The application supplies structured evidence. The next product step wires Guard decisions to the authenticated socket client and adds durable state and cross-process behavior.

The bridge client is imported from `@honeymesh/node-guard/bridge`. It signs each event with a separate HMAC secret and a fresh nonce. Supply the exact evidence hash, confidence, and short TTL only after your app has verified the source and classified the repeated behavior:

```js
import { createAgentBridge } from "@honeymesh/node-guard/bridge";

const bridge = createAgentBridge({ socketPath: "/run/honeymesh/edge.sock", secret: bridgeSecret });

const result = await bridge.sendEvent({
  sourceIp: verifiedClientIp,
  reasonCode: "invalid_signature_burst",
  evidenceHash: sha256OfRedactedEvidence,
  confidence: 90,
  ttlSeconds: 120,
});
// result.status is "observed" or "blocked" as acknowledged by the agent.
```

For the RC4 candidate multi-app agent, pass the registered `appId` in `createAgentBridge` and use the app's own socket and secret. The agent checks the signed app ID and the Linux peer UID.

The development-only [free SDK host adapter](FREE_GUARD_HOST_ADAPTER.md) accepts a **source-IP-scoped** v2 decision from the separate public `@network-decode/node-guard` package and forwards it through this authenticated bridge only when explicitly enabled. Subject, tenant, and API-key decisions cannot request a host-wide ban. The agent still checks app identity, mode, and source policy. This adapter is not in the pinned signed customer bundle and has no VM qualification yet.

`bridgeSecret` must be read from a private runtime secret source. The deployed Exchange agent uses a single app socket; the multi-app configuration is a development-branch candidate and has not been deployed.

# HoneyMesh Node Guard prototype

This is a private, framework-neutral Node.js application limiter. It is a first reusable piece of the HoneyMesh for Node.js product. It does not attach eBPF/XDP, parse HTTP headers, or publish bans to the Exchange. The current implementation keeps state in one process, so restart clears active limits. Do not publish it as a production package yet.

Pass a **verified** client address from a trusted ingress. Never pass a client-supplied `X-Forwarded-For` value. In `enforce` mode, provide `canActOnSource` to exclude operators, monitors, trusted proxies, and other local policy exceptions. Private, loopback, link-local, and multicast addresses are rejected by the library.

```js
import { createHoneyMeshGuard } from "@honeymesh/node-guard";

const operatorAddresses = new Set(); // Populate from your trusted operator policy.
const auditDecision = (decision) => console.info(decision);
// verifiedClientIp must come from your trusted ingress integration.
const guard = createHoneyMeshGuard({
  mode: "observe", // Switch to enforce only after attribution and allowlist tests.
  canActOnSource: (verifiedClientIp) => !operatorAddresses.has(verifiedClientIp),
  onDecision: (decision) => auditDecision(decision),
});

// Call this only for a real application signal, such as a failed HMAC signature.
guard.record({ sourceIp: verifiedClientIp, reasonCode: "invalid_signature_burst", protocol: "HTTPS" });

// In enforce mode, check before costly application work and return HTTP 429 if true.
if (guard.isBlocked(verifiedClientIp)) return tooManyRequests();
```

This package deliberately does not decide whether a request is malicious. The application supplies structured evidence. The next product step connects decisions to the authenticated local HoneyMesh edge socket and adds durable state and cross-process behavior.

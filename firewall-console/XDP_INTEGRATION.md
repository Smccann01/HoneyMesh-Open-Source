# Node Guard to HoneyMesh XDP boundary

## Product split

The public Node Guard SDK contains application policy logic and a documented event format. It runs without a HoneyMesh account or agent. The paid Node Pro component is a separately installed, compiled HoneyMesh agent. Keep its privileged XDP program, map reconciliation, license verification, and operator policy in that private component. A client package cannot make code it ships invisible to its users; the boundary is a service protocol, not obfuscation.

## Transport and authority

The current Node agent candidate already provides a protected Unix-socket bridge. It checks an HMAC over the exact event body, a timestamp and nonce, registered application ID, kernel-provided peer UID, source eligibility, allowed reason, confidence, TTL, entitlement, and agent mode. Successful admission can create an application-owned UEE grant. The UEE is the only XDP ban-map writer. It must preserve other owners if this app's grant expires or is withdrawn.

The browser and this synthetic lab must not submit a typed IP as if it were verified hostile traffic. A production adapter should forward only a bounded source-scoped Node Guard v2 decision derived from an application's trusted peer attribution and real observations. Secrets stay in private files accessible to the app UID; they never enter browser code or a public npm package.

The existing XDP ban map blocks an entire exact source IP. Application route throttling and per-port filtering have different scope. Show that distinction explicitly in the UI and require a policy decision before any source-wide escalation.

## Implementation sequence

1. Provision a Node Pro entitlement, one app ID, one Unix socket, one secret, and a dedicated Linux UID.
2. Integrate a server-side Node Guard decision callback with the private agent bridge. Keep the free local decision active when the agent is absent.
3. Expose read-only agent mode, app-owned grants, effective kernel state, XDP attachment, and drop totals to the operator. Distinguish `observed` from `blocked`.
4. Add app-scoped release and restart reconciliation through the UEE. Do not let the dashboard write a BPF map directly.
5. Qualify the exact signed build on a disposable VM with real IPv4/IPv6 selected and control traffic, two app UIDs, negative identity and signature tests, expiry, release, restart, and rollback. Remove the VM afterward.

## Source reviewed

- `HoneyMesh-core-release-fix/bpf/main.c`: exact-source XDP checks.
- `HoneyMesh-core-release-fix/uee_kernel_adapter.go`: UEE map writes.
- `HoneyMesh-Node/agent/internal/agentbridge/bridge.go`: signed event and peer boundary.
- `HoneyMesh-Node/agent/node_edge_apps.go`: app registration and entitlement checks.
- `HoneyMesh-Node/node-guard/free-bridge-adapter.mjs`: candidate bounded source-scoped decision forwarding.

The separately published Node Guard Free alpha does not include the private bridge. This document is an integration plan, not evidence that the lab is enforcing at XDP.

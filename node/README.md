# HoneyMesh Node

HoneyMesh Node combines a Node.js application Guard with an authenticated local bridge to a HoneyMesh Linux agent. The source is free; local application controls, scoped host grants, and direct mesh do not require a purchase. TEST is the initial agent mode, and community Exchange intelligence is observation-only by default.

The official Community agent build supports up to five direct mesh peers per node. Direct mesh requires an operator-configured cluster identity, mutually verified TLS certificates, and explicit opt-in. The receiving agent decides whether to enforce a signal. A customer-operated Community Exchange is separate from direct mesh and remains free. Local application events must identify a verified client source and pass the agent's authorization and bounded-action checks.

## Components

- `node-guard/`: in-process Node.js protection, policy tools, and examples.
- `agent/`: Linux agent source and local bridge.
- `agentbridge/`: authenticated Unix-socket bridge implementation.
- `examples/`: example application integration.

## Build and verify

```sh
cd node-guard && npm test
cd ../agent && go test ./...
```

Read [LICENSE](LICENSE), [INSTALL.md](INSTALL.md), and [SECURITY.md](SECURITY.md) before deploying. This is source code, not a signed or qualified production installer. Earlier pilot records and operational rollout details are maintained separately by Network Decode.

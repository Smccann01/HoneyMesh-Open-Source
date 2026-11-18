# Embedded HoneyMesh Node bridge

`prepare.py` builds an isolated integration tree from the exact HoneyMesh 2.3.6-rc2 source archive. It verifies the archive SHA-256, excludes `tools/license-keygen`, copies the shared signed handler, and applies fixed, fail-closed source edits. The source archive and generated tree are not committed here.

```sh
python3 agent-integration/prepare.py /path/to/honeymesh-2.3.6-rc2-source.tar.gz .build/agent-integrated
cd .build/agent-integrated
HM_NODE_CLIENT_PATH=/absolute/path/to/HoneyMesh-Node/node-guard/bridge.mjs go test ./... -count=1
go vet ./...
go build -buildvcs=false -o ../honeymesh-integrated .
test ! -e tools/license-keygen
```

The local service accepts events only when `HM_EDGE_SOCKET` points to a protected absolute Unix-socket path and `HM_EDGE_SECRET_FILE` points to a separate secret file containing at least 32 bytes. `HM_EDGE_APP_SOURCE` must bind that credential to either `exchange_guard` or `node_guard`; requests claiming the other source are rejected. The socket parent must already exist and be accessible only to the agent and authorized Node application group. The bridge refuses to replace an existing socket. `HM_EDGE_AUTOBLOCK=true` requires at least one exact, comma-separated public address in `HM_EDGE_CANARY_IPS`; only those listed sources can receive app-originated packet rules while the agent is in Enforce mode and an interface is attached. The default is observe-only. Event admission also checks signature, freshness, replay, public source address, allowlists, confidence, reason code, and a 60–300 second TTL. The callback limits accepted events to 100 per minute and one event per source and reason per minute. Independent credentials, sockets, and per-app quotas are still a release gate before multiple applications share an agent.

The agent writes `node_edge_events` to its private SQLite database. It returns `blocked` only after the BPF map write and read-back succeed. App bans expire on the agent's five-second cleanup ticker or can be released by an operator. Switching to TEST or LOCKDOWN also releases active app rules and reports a kernel removal error to the dashboard API. These rules are not sent through the mesh or Exchange publish path and are not restored after restart. On restart, the audit marks former app blocks released and incomplete attempts rejected. Keep sharing disabled unless a separate, explicitly approved sharing design is implemented.

This integration is a pre-release build. Before replacing a production agent, back up its binary, configuration, state, and database; run the veth matrix; check release and rollback; and verify public IPv4/IPv6 site health. The public Exchange currently runs the embedded bridge in TEST mode, with automatic app blocking disabled and its public interface detached.

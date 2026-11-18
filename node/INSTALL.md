# HoneyMesh.io rollout

This runbook deploys the embedded HoneyMesh Node bridge into the existing HoneyMesh.io VPS agent. It is scoped to the already running Exchange app and HoneyMesh 2.3.6-rc2 service. The first rollout stays in **TEST** mode with `HM_EDGE_AUTOBLOCK=false` and no XDP attachment on `eth0`. It replaces the observe-only pilot sidecar after the embedded socket passes authentication and the public activity API reports a connected TEST agent.

The current hardened TEST-mode build adds an exact-source gate, one-source credential binding, and TEST-mode release of app packet rules. The private `v0.3.0-canary-hardening` prerelease contains the exact binary deployed on HoneyMesh.io. The older `v0.2.0-exchange-pilot` prerelease is retained as a rollback artifact. Public-ingress blocking is still a separate canary gate in [the runbook](CANARY_RUNBOOK.md).

## Build and stage

The private repository contains the keygen-free integrated agent source, Node Guard, tests, and deployment scripts. An admin with access to the private GitHub repository can download the tested prerelease binary:

```sh
git clone git@github.com:Smccann01/HoneyMesh-Node.git
cd HoneyMesh-Node
mkdir -p dist
gh release download v0.3.0-canary-hardening --repo Smccann01/HoneyMesh-Node --dir dist
(cd dist && sha256sum -c SHA256SUMS)
```

To build it instead, use Linux AMD64 with Go 1.26.10 and Node 20 or newer:

```sh
git clone git@github.com:Smccann01/HoneyMesh-Node.git
cd HoneyMesh-Node
./scripts/build-release.sh
```

The build runs the Go and Node tests, `go vet`, and writes `dist/honeymesh-node-agent` plus `dist/SHA256SUMS`. The binary is a private prerelease, separate from the original rc2 Debian package. Keep `dist/` and all runtime credentials out of Git.

Copy the binary, checksum file, and `scripts/exchange-deploy.sh`, `scripts/exchange-rollback.sh`, and `scripts/exchange-smoke.py` to a root-only directory on the HoneyMesh.io VPS. The Exchange must already have its Node application, `honeymesh.service`, `honeymesh-exchange.service`, bridge socket configuration, and separate bridge secret. The deploy script checks those prerequisites, service health, private secret permissions, and a detached `eth0`.

```sh
ssh root@YOUR_VPS 'install -d -m 0700 /root/honeymesh-node-rollout/dist /root/honeymesh-node-rollout/scripts'
scp dist/honeymesh-node-agent dist/SHA256SUMS root@YOUR_VPS:/root/honeymesh-node-rollout/dist/
scp scripts/exchange-deploy.sh scripts/exchange-rollback.sh scripts/exchange-smoke.py root@YOUR_VPS:/root/honeymesh-node-rollout/scripts/
ssh root@YOUR_VPS 'cd /root/honeymesh-node-rollout && bash scripts/exchange-deploy.sh check'
ssh root@YOUR_VPS 'cd /root/honeymesh-node-rollout && bash scripts/exchange-deploy.sh install dist/honeymesh-node-agent'
```

The installer verifies the SHA-256 manifest, creates a root-only backup of the prior binary, operator config, runtime state, Exchange environment, and a consistent SQLite backup. It arms an automatic rollback timer, stops the pilot sidecar, installs the integrated binary, and gives the agent ownership of the existing protected socket. It validates a signed socket query and the public activity API before disabling the pilot service. The output prints the exact rollback command and backup path. The Exchange app stays running during the socket handover.

## Verify and roll back

After install, verify the service states, socket permissions, public activity page, and IPv4/IPv6 site health. The expected state is `agentStatus: connected`, `agentMode: TEST`, zero agent app blocks, and no XDP program on `eth0`. Keep automatic blocking off until a controlled public-ingress canary has an external test source, a separate control source, an operator release, and a timed rollback.

Use the rollback command printed by the installer to restore the prior agent binary and pilot sidecar. The SQLite backup remains in the root-only backup directory for investigation; rollback does not overwrite the live database or discard events written during the test. The additive `node_edge_events` table is ignored by the old agent.

The app's `EXCHANGE_EDGE_SECRET` and the agent's private secret file must match. If they do not, the signed smoke test or public API check fails and the installer restores the prior service. Do not put the secret, runtime state, or private license generator into a release archive or issue log.

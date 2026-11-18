# Node Guard Free candidate: clean developer setup

**Current scope:** private `0.2.0-alpha.6` candidate for internal evaluation. This is not a public npm release or a production-qualified customer install guide.

## Build and verify the exact local package

From `HoneyMesh-Node/node-guard` on Node.js 20 or newer:

```sh
npm ci
npm test
npm run smoke:package
npm pack --pack-destination /tmp
```

The smoke command creates a disposable app, installs the packed archive without a license, runs `nodeguard init` and `doctor`, then checks local enforcement and trusted-source resolution. `npm pack` prints the archive name. Keep its checksum and source revision with any internal test record.

## Install into a separate noncritical test app

In that app, install the tarball and Express if the app does not already use Express:

```sh
npm install /tmp/honeymesh-node-guard-0.2.0-alpha.6.tgz express
npx nodeguard init
npx nodeguard doctor nodeguard.policy.json
npx nodeguard policy validate nodeguard.policy.json
```

`init` writes an OBSERVE policy and refuses to overwrite it. Set its application and route IDs to match the app. Review the real socket peer, proxy behavior, and operator exclusions before considering ENFORCE. The trusted-source resolver requires exact proxy IPs, and each trusted proxy must append or replace `X-Forwarded-For` with the peer it actually observed. Do not trust a header sent directly by a client.

The v1 runtime accepts one policy for one application and route per instance. Mount the Express middleware only on that route and generate observations from actual application security events. `nodeguard policy test` is a local simulation; it does not enable enforcement. The candidate keeps counters in one process and clears them on restart, so clustered or replicated applications are outside this setup's enforcement scope.

The existing Node Pro agent bridge is a separate authenticated and licensed host-level path. Installing this free candidate does not authorize XDP or Exchange actions.

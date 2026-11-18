# Independent Node service pilot

This small HTTP service consumes `@honeymesh/node-guard` through its package export. It contains no Exchange source. It exercises verified client-IP attribution, repeated bad API signatures, application limits, and optional signed evidence to a local HoneyMesh agent. It is a reference app for tests, not a production authentication service.

## Run locally

Use Node 20 or newer. `npm ci` installs the sibling package from `../../node-guard`. Keep all keys out of Git.

```sh
cd examples/reference-service
npm ci
npm test
install -m 0600 /dev/null /tmp/reference-signing-key
openssl rand -hex 32 > /tmp/reference-signing-key
REFERENCE_SIGNING_KEY_FILE=/tmp/reference-signing-key npm start
curl http://127.0.0.1:3101/healthz
```

The service listens on `127.0.0.1:3101` by default. `REFERENCE_BIND_IP` is available for an isolated network-namespace test; never bind it to a public interface without a reviewed ingress policy. It defaults to observe mode and does not connect to an agent unless both `HM_EDGE_SOCKET` and `HM_EDGE_SECRET_FILE` are configured. Enforce mode also requires exact `REFERENCE_CANARY_IPS`, and an authenticated proxy source must be configured before public requests can be attributed. In observe mode, repeated invalid signatures produce decisions but do not return HTTP 429.

## Proxy and source identity

If deployed behind nginx on the same host, set `REFERENCE_TRUSTED_PROXY_PEERS=127.0.0.1,::1`, bind the app to loopback, and make nginx overwrite `X-Real-IP` with `$remote_addr` on every proxied request. Do not pass through the client's `X-Real-IP` or use untrusted `X-Forwarded-For` values. Verify the loaded config and a forged-header request before enabling enforce mode. The resolver ignores a forwarded header from any peer outside the configured proxy list.

```nginx
location /reference/ {
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_pass http://127.0.0.1:3101/;
}
```

This app emits `source: node_guard`. To use the candidate multi-app agent bridge, configure its own socket, secret, Linux UID, and `HM_EDGE_APP_ID`; see [multi-app setup](../../agent/NODE_EDGE_MULTI_APP.md). The existing Exchange socket and secret remain separate. The two-app production pilot is still an open release gate.

The guard stores its short window in one process. Restarting the app clears its application limits, and multiple workers do not share state. Keep the pilot to one worker and report those limits in any demonstration. The Node process needs no root privileges, BPF capability, or HoneyMesh admin token.

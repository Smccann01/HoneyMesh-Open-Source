# Node Guard 0.2.0 alpha.6 pilot install pack

The release provides a free npm tarball and a matching `SHA256SUMS` file. It is a Node.js application SDK, not a Linux host installer. Node.js 20 or newer is required. It starts in OBSERVE mode when initialized with the included CLI. Review the trusted source and policy guides before ENFORCE.

Download the tarball and `SHA256SUMS` from the same release into one directory. Verify both the checksum and the GitHub artifact attestation for the public `Smccann01/HoneyMesh-Open-Source` repository:

```sh
sha256sum -c SHA256SUMS
gh attestation verify honeymesh-node-guard-0.2.0-alpha.6.tgz -R Smccann01/HoneyMesh-Open-Source
npm install ./honeymesh-node-guard-0.2.0-alpha.6.tgz
npx nodeguard init --output nodeguard.policy.json
npx nodeguard doctor nodeguard.policy.json
```

The installed SDK does not become a reverse proxy or a host firewall by itself. Integrate it with your Node.js request handlers and verify client-IP attribution before enabling enforcement. The optional host adapter remains disabled until separately configured and qualified. See `README.md`, `DEVELOPER_SETUP.md`, and `NEXT_ROUTE_GUIDE.md` in the package source.

# HoneyMesh Exchange

The self-hosted Exchange provides authenticated enrollment, signed machine APIs, a network admin console, and opt-in defensive observation sharing. It is licensed under [AGPL-3.0-only](LICENSE). Each installation provisions its own administrator and stores its own credentials and data.

## Local setup

Install dependencies, configure a private durable SQLite database path, and build the app:

```sh
npm ci
npm run build
```

Run `scripts/provision-network-admin.mjs` on a trusted setup host with explicit `--db`, `--credentials-out`, `--email`, `--tenant`, `--cluster`, and `--origin` arguments. It creates a unique password and authenticator secret in a new owner-only file. Keep that file outside the repository. Admin sessions use short-lived random tokens stored as hashes.

An authenticated admin can create a one-use, ten-minute enrollment token through `POST /api/admin/enrollment-token`. A node enrolls through `POST /api/hm/enroll` and receives its own secret once. Sharing and discovery start disabled; the admin must opt in. Community observations are review-only and cannot directly order a receiving host to enforce a block.

## Verify

```sh
npm run test:network-admin
npm run test:discovery
npm run test:protocol
npm run build
```

Use one writer process for the SQLite database, protect backups, and prove restore before production use. Review [SECURITY.md](SECURITY.md) and the machine API documentation before deployment. This repository does not contain Network Decode's managed-service configuration or operational records.

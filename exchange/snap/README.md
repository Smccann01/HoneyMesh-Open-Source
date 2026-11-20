# Exchange Snap developer pilot

This is an unpublished, strictly confined Ubuntu 24.04 AMD64 candidate. It
does not start on installation. It stores its SQLite database, generated
configuration, and administrator recovery file under
`/var/snap/network-decode-exchange/common/private/` with owner-only access.

Initialize on a noncritical host, using the HTTPS origin that a trusted reverse
proxy will serve:

```sh
sudo snap run network-decode-exchange.init \
  --origin=https://exchange.example.com \
  --email=admin@example.com --tenant=example --cluster=example-cluster
sudo cat /var/snap/network-decode-exchange/common/private/admin-credentials.txt
sudo snap start --enable network-decode-exchange
```

The application listens only on `127.0.0.1:8790`. Put an HTTPS reverse proxy
in front of it, forwarding the original Host and protocol headers. Do not
expose port 8790 directly. The administrator credentials file is written once;
setup refuses to replace it. Keep a separate private recovery copy after the
first sign-in. Sharing and discovery start disabled.

For a verified SQLite backup and service recovery:

```sh
sudo snap run network-decode-exchange.backup
sudo snap stop --disable network-decode-exchange
sudo snap services network-decode-exchange
```

The backup command writes an integrity-checked copy under the Snap's private
`backups/` directory by default. Restore testing, real version refresh,
enrollment, and proxy setup remain release gates in [issue #32](https://github.com/Smccann01/HoneyMesh-Open-Source/issues/32).

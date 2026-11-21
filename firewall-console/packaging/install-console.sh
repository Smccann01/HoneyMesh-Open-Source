#!/bin/sh
set -eu

fail() { printf 'Firewall console install: %s\n' "$1" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || fail 'run as root after verifying the signed bundle'
[ "$#" -eq 1 ] || fail 'usage: install-console.sh BUNDLE_DIRECTORY'
bundle=$1
[ -f "$bundle/network-decode-firewall-console-0.2.1-beta.9.tgz" ] || fail 'console archive missing'
[ -f "$bundle/package-lock.json" ] || fail 'lockfile missing'
[ -f "$bundle/network-decode-firewall.service" ] || fail 'service file missing'
[ -f /etc/honeymesh/certs/node/node.crt ] || fail 'install and start the signed HoneyMesh host agent first'
[ -f /etc/honeymesh/certs/ca/ca.crt ] || fail 'HoneyMesh local CA certificate is missing'
openssl verify -CAfile /etc/honeymesh/certs/ca/ca.crt /etc/honeymesh/certs/node/node.crt >/dev/null || fail 'HoneyMesh node certificate is not signed by the local CA'
[ ! -e /opt/network-decode-firewall/current ] && [ ! -L /opt/network-decode-firewall/current ] || fail 'an existing console release is present; use the reviewed upgrade procedure'
[ ! -e /etc/systemd/system/network-decode-firewall.service ] || fail 'an existing console service is present; use the reviewed upgrade procedure'
command -v node >/dev/null 2>&1 || fail 'Node.js 20 or newer is required at /usr/bin/node'
[ "$(command -v node)" = /usr/bin/node ] || fail 'Node.js must be installed at /usr/bin/node'
node -e 'process.exit(Number(process.versions.node.split(".")[0]) >= 20 ? 0 : 1)' || fail 'Node.js 20 or newer is required'
command -v npm >/dev/null 2>&1 || fail 'npm is required to install pinned dependencies'

if ! id networkdecode >/dev/null 2>&1; then
  useradd --system --home-dir /var/lib/network-decode-firewall --shell /usr/sbin/nologin networkdecode
fi
install -d -o root -g root -m 0755 /opt/network-decode-firewall /opt/network-decode-firewall/releases
release=/opt/network-decode-firewall/releases/0.2.1-beta.9
[ ! -e "$release" ] || fail 'release directory already exists; stop and review the existing installation'
stage=$(mktemp -d /opt/network-decode-firewall/releases/.install-XXXXXX)
installed=false
created_release=false
created_link=false
created_unit=false
cleanup_failed_install() {
  status=$?
  trap - EXIT
  if [ "$status" -ne 0 ] && [ "$installed" != true ]; then
    if [ "$created_unit" = true ]; then
      systemctl disable --now network-decode-firewall.service >/dev/null 2>&1 || true
      rm -f /etc/systemd/system/network-decode-firewall.service
      systemctl daemon-reload >/dev/null 2>&1 || true
    fi
    if [ "$created_link" = true ] && [ "$(readlink /opt/network-decode-firewall/current)" = "$release" ]; then
      rm -f /opt/network-decode-firewall/current
    fi
    rm -rf "$stage"
    if [ "$created_release" = true ]; then rm -rf "$release"; fi
  fi
  exit "$status"
}
trap cleanup_failed_install EXIT
tar -xzf "$bundle/network-decode-firewall-console-0.2.1-beta.9.tgz" --strip-components=1 -C "$stage"
install -o root -g root -m 0644 "$bundle/package-lock.json" "$stage/package-lock.json"
(cd "$stage" && npm ci --omit=dev --ignore-scripts --no-audit --no-fund)
chown -R root:networkdecode "$stage"
# Extraction inherits the caller's umask. Grant the service group access to
# every package directory and readable file, even when root uses umask 077.
# Other local users cannot read the closed console package.
chmod -R g+rX,o-rwx "$stage"
chmod -R go-w "$stage"
chmod 0750 "$stage"
mv -T "$stage" "$release"
created_release=true

install -d -o networkdecode -g networkdecode -m 0700 /var/lib/network-decode-firewall
fingerprint=$(openssl x509 -in /etc/honeymesh/certs/node/node.crt -noout -fingerprint -sha256 | cut -d= -f2)
printf '%s\n' "$fingerprint" | grep -Eq '^([A-Fa-f0-9]{2}:){31}[A-Fa-f0-9]{2}$' || fail 'invalid agent certificate fingerprint'
printf '{"url":"https://127.0.0.1:8443","fingerprint_sha256":"%s"}\n' "$fingerprint" > /var/lib/network-decode-firewall/agent-public.json
chown networkdecode:networkdecode /var/lib/network-decode-firewall/agent-public.json
chmod 0600 /var/lib/network-decode-firewall/agent-public.json
install -o networkdecode -g networkdecode -m 0600 /etc/honeymesh/certs/ca/ca.crt /var/lib/network-decode-firewall/agent-ca.crt

ln -s "$release" /opt/network-decode-firewall/current
created_link=true
install -o root -g root -m 0644 "$bundle/network-decode-firewall.service" /etc/systemd/system/network-decode-firewall.service
created_unit=true
systemctl daemon-reload
systemctl enable --now network-decode-firewall.service
ready=false
attempt=0
while [ "$attempt" -lt 30 ]; do
  if curl --fail --silent --show-error --max-time 2 http://127.0.0.1:8787/health >/dev/null 2>&1; then
    ready=true
    break
  fi
  attempt=$((attempt + 1))
  sleep 1
done
if [ "$ready" != true ]; then
  systemctl status network-decode-firewall.service --no-pager --lines=15 >&2 || true
  fail 'service did not become healthy; inspect journalctl -u network-decode-firewall.service'
fi
installed=true
printf 'Firewall console installed on http://127.0.0.1:8787 in read-only host mode.\n'
printf 'Retrieve the one-time local bootstrap token with:\n'
printf "  sudo -u networkdecode node -p 'require(\"/var/lib/network-decode-firewall/credentials.json\").adminToken'\n"

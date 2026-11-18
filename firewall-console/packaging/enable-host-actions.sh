#!/bin/sh
set -eu

fail() { printf 'Firewall host actions: %s\n' "$1" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || fail 'run as root from a verified signed bundle'
[ "${1:-}" = 'ENABLE SCOPED HOST ACTIONS' ] || fail 'usage: enable-host-actions.sh "ENABLE SCOPED HOST ACTIONS"'
[ "$#" -eq 1 ] || fail 'unexpected arguments'
[ -L /opt/network-decode-firewall/current ] || fail 'matching Firewall console is not installed'
[ -f /etc/systemd/system/network-decode-firewall.service ] || fail 'console service is missing'
[ ! -e /etc/systemd/system/network-decode-firewall.service.d/90-scoped-actions.conf ] || fail 'host-action override already exists; review it before retrying'
systemctl is-active --quiet network-decode-firewall.service || fail 'console service is not active'
systemctl is-active --quiet honeymesh.service || fail 'HoneyMesh agent is not active'

python3 - <<'PY' || fail 'paid agent contract or local admin account is not ready in TEST'
import json, ssl, urllib.request
from pathlib import Path

token = json.loads(Path('/var/lib/honeymesh/runtime-state.json').read_text())['admin_token']
context = ssl.create_default_context(cafile='/etc/honeymesh/certs/ca/ca.crt')
request = urllib.request.Request('https://127.0.0.1:8443/api/enforcement/contract',
                                 headers={'X-Honey-Token': token})
with urllib.request.urlopen(request, context=context, timeout=8) as response:
    contract = json.load(response)
assert contract['contract_version'] == 1
assert contract['operator_grants'] is True and contract['scoped_release'] is True
assert contract['uee_ready'] is True and contract['mode'] == 'TEST'
with urllib.request.urlopen('http://127.0.0.1:8787/api/account/state', timeout=8) as response:
    account = json.load(response)
assert account['configured'] is True
PY

override_dir=/etc/systemd/system/network-decode-firewall.service.d
install -d -o root -g root -m 0755 "$override_dir"
override=$override_dir/90-scoped-actions.conf
trap 'rm -f -- "$override"; systemctl daemon-reload; systemctl restart network-decode-firewall.service' EXIT
cat >"$override" <<'UNIT'
[Service]
Environment=HM_HOST_ACTIONS_ENABLED=1
UNIT
chmod 0644 "$override"
systemctl daemon-reload
systemctl restart network-decode-firewall.service
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
[ "$ready" = true ] || fail 'console did not restart; override removed by rollback trap'
systemctl show -p Environment --value network-decode-firewall.service | grep -q 'HM_HOST_ACTIONS_ENABLED=1' || fail 'host-action setting not active'
trap - EXIT
printf 'Scoped host actions enabled. HoneyMesh remains in TEST; review sources, control traffic, and rollback before ENFORCE.\n'

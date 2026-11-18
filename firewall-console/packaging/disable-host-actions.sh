#!/bin/sh
set -eu

fail() { printf 'Firewall host actions: %s\n' "$1" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || fail 'run as root'
[ "$#" -eq 0 ] || fail 'usage: disable-host-actions.sh'
override=/etc/systemd/system/network-decode-firewall.service.d/90-scoped-actions.conf
[ -f "$override" ] || fail 'the scoped-action override is not present'
[ "$(wc -l < "$override")" -eq 2 ] || fail 'override was modified; review it manually'
grep -Fxq '[Service]' "$override" || fail 'override was modified; review it manually'
grep -Fxq 'Environment=HM_HOST_ACTIONS_ENABLED=1' "$override" || fail 'override was modified; review it manually'
rm -- "$override"
systemctl daemon-reload
systemctl restart network-decode-firewall.service
systemctl is-active --quiet network-decode-firewall.service || fail 'console did not restart; inspect systemctl status'
printf 'Scoped host actions disabled. Existing HoneyMesh grants are unchanged; use the agent or SOC for release.\n'

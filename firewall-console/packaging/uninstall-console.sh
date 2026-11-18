#!/bin/sh
set -eu

fail() { printf 'Firewall console removal: %s\n' "$1" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || fail 'run as root from the verified bundle'
[ "$#" -eq 1 ] || fail 'usage: uninstall-console.sh BUNDLE_DIRECTORY'
bundle=$1
[ -f "$bundle/network-decode-firewall.service" ] || fail 'matching service file missing'
unit=/etc/systemd/system/network-decode-firewall.service
release=/opt/network-decode-firewall/releases/0.2.1-beta.9
current=/opt/network-decode-firewall/current
[ -L "$current" ] && [ "$(readlink "$current")" = "$release" ] || fail 'current release is not beta.9; stop and review it'
[ -f "$unit" ] && cmp -s "$unit" "$bundle/network-decode-firewall.service" || fail 'installed service differs from this bundle'
[ -d "$release" ] && [ ! -L "$release" ] || fail 'release directory is missing or replaced by a link'

systemctl disable --now network-decode-firewall.service
unlink "$current"
unlink "$unit"
systemctl daemon-reload
rm -rf -- "$release"
printf 'Firewall console removed. HoneyMesh and private state at /var/lib/network-decode-firewall were preserved.\n'

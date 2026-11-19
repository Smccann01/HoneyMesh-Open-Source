#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
out=${1:-"$root/dist/pilot"}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
name=network-decode-firewall-console-0.2.1-beta.9
stage="$work/$name"
mkdir -p "$stage" "$out"
(cd "$root" && npm ci --ignore-scripts --no-audit --no-fund && npm test && npm pack --pack-destination "$stage" --silent)
install -m 0644 "$root/package-lock.json" "$stage/package-lock.json"
for file in network-decode-firewall.service install-console.sh uninstall-console.sh enable-host-actions.sh disable-host-actions.sh; do
  install -m 0644 "$root/packaging/$file" "$stage/$file"
done
install -m 0644 "$root/packaging/FREE_PILOT_INSTALL.md" "$stage/FREE_PILOT_INSTALL.md"
install -m 0644 "$root/LICENSE" "$stage/LICENSE"
(cd "$work" && tar --sort=name --mtime='@0' --owner=0 --group=0 --numeric-owner -cf - "$name" | gzip -n > "$out/$name-free-pilot.tar.gz")
(cd "$out" && sha256sum "$name-free-pilot.tar.gz" > SHA256SUMS && sha256sum -c SHA256SUMS)
echo "Built $out/$name-free-pilot.tar.gz"

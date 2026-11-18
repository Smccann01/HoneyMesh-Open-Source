#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
release_dir="${1:-$repo_dir/dist}"

if [[ "$(go env GOOS)" != linux || "$(go env GOARCH)" != amd64 ]]; then
  echo 'Build on Linux AMD64 for the Exchange VPS.' >&2
  exit 1
fi
if [[ -e "$repo_dir/agent/tools/license-keygen" ]]; then
  echo 'Private license keygen must not be in the release tree.' >&2
  exit 1
fi

(cd "$repo_dir/agent" && go test ./... -count=1 && go vet ./...)
(cd "$repo_dir/agentbridge" && go test ./... -count=1 && go vet ./...)
(cd "$repo_dir/node-guard" && npm test)
(cd "$repo_dir/examples/reference-service" && npm ci --ignore-scripts --no-audit --no-fund && npm test)
mkdir -p "$release_dir"
(cd "$repo_dir/agent" && go build -trimpath -buildvcs=false -o "$release_dir/honeymesh-node-agent" .)
chmod 0755 "$release_dir/honeymesh-node-agent"
(cd "$release_dir" && sha256sum honeymesh-node-agent > SHA256SUMS)
echo "Built $release_dir/honeymesh-node-agent"

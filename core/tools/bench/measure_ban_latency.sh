#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<USAGE
Usage: $0 --url https://127.0.0.1:8443 --token <admin_token> --ip <test_ip> \
          [--peer-url https://peer:8443] [--timeout-ms 10000] [--poll-ms 50]

Measures:
  - local ban API round-trip latency
  - local ban visibility latency via /api/bans
  - optional peer visibility latency via /api/bans on peer-url
USAGE
}

URL=""
TOKEN=""
TEST_IP=""
PEER_URL=""
TIMEOUT_MS=10000
POLL_MS=50

while [[ $# -gt 0 ]]; do
  case "$1" in
    --url) URL="$2"; shift 2 ;;
    --token) TOKEN="$2"; shift 2 ;;
    --ip) TEST_IP="$2"; shift 2 ;;
    --peer-url) PEER_URL="$2"; shift 2 ;;
    --timeout-ms) TIMEOUT_MS="$2"; shift 2 ;;
    --poll-ms) POLL_MS="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 1 ;;
  esac
done

if [[ -z "$URL" || -z "$TOKEN" || -z "$TEST_IP" ]]; then
  echo "--url, --token, and --ip are required" >&2
  exit 1
fi

post_json() {
  local endpoint="$1"
  local body="$2"
  curl -skS \
    -H "X-Honey-Token: $TOKEN" \
    -H "Content-Type: application/json" \
    -X POST \
    -d "$body" \
    "$endpoint"
}

has_ip_in_bans() {
  local base="$1"
  local bans
  bans="$(curl -skS -H "X-Honey-Token: $TOKEN" "$base/api/bans" || true)"
  printf '%s' "$bans" | grep -Fq "\"$TEST_IP\""
}

wait_for_ban() {
  local base="$1"
  local start_ns="$2"
  local timeout_ns=$(( TIMEOUT_MS * 1000000 ))
  local poll_s
  poll_s="$(awk -v ms="$POLL_MS" 'BEGIN { printf "%.3f", ms/1000 }')"

  while true; do
    now_ns="$(date +%s%N)"
    elapsed_ns=$(( now_ns - start_ns ))
    if has_ip_in_bans "$base"; then
      echo "$elapsed_ns"
      return 0
    fi
    if [[ "$elapsed_ns" -ge "$timeout_ns" ]]; then
      return 1
    fi
    sleep "$poll_s"
  done
}

release_ban() {
  local base="$1"
  post_json "$base/api/ban/release" "{\"ip\":\"$TEST_IP\"}" >/dev/null || true
}

# Clean up stale test ban first.
release_ban "$URL"
if [[ -n "$PEER_URL" ]]; then
  release_ban "$PEER_URL"
fi

start_api_ns="$(date +%s%N)"
post_json "$URL/api/ban" "{\"ip\":\"$TEST_IP\",\"reason\":\"bench-latency\"}" >/dev/null
end_api_ns="$(date +%s%N)"
api_rtt_ns=$(( end_api_ns - start_api_ns ))

local_visible_ns=""
if local_visible_ns="$(wait_for_ban "$URL" "$start_api_ns")"; then
  :
else
  echo "local_visibility_timeout_ms=$TIMEOUT_MS" >&2
  release_ban "$URL"
  exit 2
fi

peer_visible_ns=""
if [[ -n "$PEER_URL" ]]; then
  if peer_visible_ns="$(wait_for_ban "$PEER_URL" "$start_api_ns")"; then
    :
  else
    echo "peer_visibility_timeout_ms=$TIMEOUT_MS" >&2
    release_ban "$URL"
    release_ban "$PEER_URL"
    exit 3
  fi
fi

echo "url=$URL"
echo "test_ip=$TEST_IP"
echo "api_rtt_ms=$(awk -v ns="$api_rtt_ns" 'BEGIN { printf "%.3f", ns/1000000 }')"
echo "local_visibility_ms=$(awk -v ns="$local_visible_ns" 'BEGIN { printf "%.3f", ns/1000000 }')"
if [[ -n "$peer_visible_ns" ]]; then
  echo "peer_url=$PEER_URL"
  echo "peer_visibility_ms=$(awk -v ns="$peer_visible_ns" 'BEGIN { printf "%.3f", ns/1000000 }')"
fi

release_ban "$URL"
if [[ -n "$PEER_URL" ]]; then
  release_ban "$PEER_URL"
fi

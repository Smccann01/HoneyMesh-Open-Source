#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<USAGE
Usage: $0 --target <ip-or-host> [--ports "80,443,8080"] [--workers 32] [--duration 120]

Best-effort TCP connection burst generator using bash /dev/tcp.
For higher packet rates, prefer hping3 or tcpreplay on a separate attack host.
USAGE
}

TARGET=""
PORTS=""
WORKERS=32
DURATION=120

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)
      TARGET="$2"
      shift 2
      ;;
    --ports)
      PORTS="$2"
      shift 2
      ;;
    --workers)
      WORKERS="$2"
      shift 2
      ;;
    --duration)
      DURATION="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ -z "$TARGET" ]]; then
  echo "--target is required" >&2
  exit 1
fi

if [[ -z "$PORTS" ]]; then
  PORTS="21,23,25,80,110,143,443,445,5432,6379,8080,9200"
fi

IFS=',' read -r -a PORT_ARR <<< "$PORTS"
if [[ "${#PORT_ARR[@]}" -eq 0 ]]; then
  echo "No ports configured" >&2
  exit 1
fi

echo "[traffic] target=$TARGET ports=$PORTS workers=$WORKERS duration=${DURATION}s"

worker() {
  local id="$1"
  local end_ts
  end_ts=$(( $(date +%s) + DURATION ))
  while [[ "$(date +%s)" -lt "$end_ts" ]]; do
    for p in "${PORT_ARR[@]}"; do
      # shellcheck disable=SC2094
      (exec 3<>"/dev/tcp/$TARGET/$p" && printf 'PING\r\n' >&3 && exec 3<&- 3>&-) >/dev/null 2>&1 || true
    done
  done
  echo "[traffic] worker=$id done"
}

pids=()
for i in $(seq 1 "$WORKERS"); do
  worker "$i" &
  pids+=("$!")
done

for p in "${pids[@]}"; do
  wait "$p"
done

echo "[traffic] complete"

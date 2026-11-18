#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<USAGE
Usage: $0 [--pid <pid>] [--duration 300] [--interval 1] [--out-dir ./dist/bench]

Runs an idle profile for a running honeymesh process.
USAGE
}

PID=""
DURATION=300
INTERVAL=1
OUT_DIR="./dist/bench"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --pid)
      PID="$2"
      shift 2
      ;;
    --duration)
      DURATION="$2"
      shift 2
      ;;
    --interval)
      INTERVAL="$2"
      shift 2
      ;;
    --out-dir)
      OUT_DIR="$2"
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

if [[ -z "$PID" ]]; then
  PID="$(pgrep -xo honeymesh || true)"
fi

if [[ -z "$PID" ]]; then
  echo "No running honeymesh process found. Pass --pid explicitly." >&2
  exit 1
fi

echo "[idle] profiling pid=$PID duration=${DURATION}s interval=${INTERVAL}s"
"$(dirname "$0")/profile_pid.sh" \
  --pid "$PID" \
  --duration "$DURATION" \
  --interval "$INTERVAL" \
  --out-dir "$OUT_DIR"

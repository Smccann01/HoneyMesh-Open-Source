#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<USAGE
Usage: $0 [--pid <pid>] [--duration 300] [--interval 1] [--out-dir ./dist/bench] \
          [--attack-cmd "..."] [--target <ip>] [--ports "80,443"] [--workers 64]

Profiles a running honeymesh process while generating hostile traffic.
- If --attack-cmd is set, that command is used.
- Otherwise, built-in TCP burst is used when --target is provided.
USAGE
}

PID=""
DURATION=300
INTERVAL=1
OUT_DIR="./dist/bench"
ATTACK_CMD=""
TARGET=""
PORTS=""
WORKERS=64
WARMUP=10
COOLDOWN=10

while [[ $# -gt 0 ]]; do
  case "$1" in
    --pid) PID="$2"; shift 2 ;;
    --duration) DURATION="$2"; shift 2 ;;
    --interval) INTERVAL="$2"; shift 2 ;;
    --out-dir) OUT_DIR="$2"; shift 2 ;;
    --attack-cmd) ATTACK_CMD="$2"; shift 2 ;;
    --target) TARGET="$2"; shift 2 ;;
    --ports) PORTS="$2"; shift 2 ;;
    --workers) WORKERS="$2"; shift 2 ;;
    --warmup) WARMUP="$2"; shift 2 ;;
    --cooldown) COOLDOWN="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 1 ;;
  esac
done

if [[ -z "$PID" ]]; then
  PID="$(pgrep -xo honeymesh || true)"
fi
if [[ -z "$PID" ]]; then
  echo "No running honeymesh process found. Pass --pid explicitly." >&2
  exit 1
fi

if [[ "$DURATION" -le $(( WARMUP + COOLDOWN + 1 )) ]]; then
  echo "duration must be greater than warmup+cooldown+1" >&2
  exit 1
fi

if [[ -z "$ATTACK_CMD" && -z "$TARGET" ]]; then
  echo "Set --attack-cmd or --target for built-in traffic generator." >&2
  exit 1
fi

mkdir -p "$OUT_DIR"
ATTACK_DURATION=$(( DURATION - WARMUP - COOLDOWN ))

if [[ -z "$ATTACK_CMD" ]]; then
  ATTACK_CMD="$(dirname "$0")/traffic_tcp_burst.sh --target $TARGET --duration $ATTACK_DURATION --workers $WORKERS"
  if [[ -n "$PORTS" ]]; then
    ATTACK_CMD+=" --ports $PORTS"
  fi
fi

echo "[attack] pid=$PID duration=${DURATION}s warmup=${WARMUP}s attack=${ATTACK_DURATION}s cooldown=${COOLDOWN}s"
echo "[attack] command=$ATTACK_CMD"

"$(dirname "$0")/profile_pid.sh" \
  --pid "$PID" \
  --duration "$DURATION" \
  --interval "$INTERVAL" \
  --out-dir "$OUT_DIR" &
PROF_PID=$!

sleep "$WARMUP"
set +e
timeout "$ATTACK_DURATION" bash -lc "$ATTACK_CMD"
ATTACK_RC=$?
set -e
sleep "$COOLDOWN"

wait "$PROF_PID"

echo "attack_command_exit_code=$ATTACK_RC"
if [[ "$ATTACK_RC" -ne 0 && "$ATTACK_RC" -ne 124 ]]; then
  echo "Attack command exited with non-zero status" >&2
  exit "$ATTACK_RC"
fi

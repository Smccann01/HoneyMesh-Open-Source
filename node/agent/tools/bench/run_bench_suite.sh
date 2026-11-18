#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BENCH_DIR="$ROOT_DIR/tools/bench"

OUT_DIR="${BENCH_OUT_DIR:-$ROOT_DIR/dist/bench}"
PID="${BENCH_PID:-}"
IDLE_DURATION="${BENCH_IDLE_DURATION:-300}"
ATTACK_DURATION="${BENCH_ATTACK_DURATION:-300}"
INTERVAL="${BENCH_INTERVAL:-1}"
ATTACK_CMD="${BENCH_ATTACK_CMD:-}"
TARGET="${BENCH_TARGET:-127.0.0.1}"
PORTS="${BENCH_PORTS:-21,23,25,80,110,143,443,445,5432,6379,8080,9200}"
WORKERS="${BENCH_WORKERS:-64}"
URL="${BENCH_URL:-https://127.0.0.1:8443}"
TOKEN="${BENCH_TOKEN:-}"
TEST_IP="${BENCH_TEST_IP:-203.0.113.77}"
PEER_URL="${BENCH_PEER_URL:-}"

usage() {
  cat <<USAGE
Usage: $0 [--token <admin-token>] [--url https://127.0.0.1:8443]

Runs full benchmark suite:
  1) idle CPU/RSS profile
  2) attack CPU/RSS profile
  3) ban latency (if token is provided)
  4) consolidated markdown report

All settings can be overridden via BENCH_* environment variables.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --token) TOKEN="$2"; shift 2 ;;
    --url) URL="$2"; shift 2 ;;
    --peer-url) PEER_URL="$2"; shift 2 ;;
    --pid) PID="$2"; shift 2 ;;
    --out-dir) OUT_DIR="$2"; shift 2 ;;
    --idle-duration) IDLE_DURATION="$2"; shift 2 ;;
    --attack-duration) ATTACK_DURATION="$2"; shift 2 ;;
    --interval) INTERVAL="$2"; shift 2 ;;
    --attack-cmd) ATTACK_CMD="$2"; shift 2 ;;
    --target) TARGET="$2"; shift 2 ;;
    --ports) PORTS="$2"; shift 2 ;;
    --workers) WORKERS="$2"; shift 2 ;;
    --test-ip) TEST_IP="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; usage; exit 1 ;;
  esac
done

mkdir -p "$OUT_DIR"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
REPORT="$OUT_DIR/bench_report_${STAMP}.md"
LAT_OUT="$OUT_DIR/latency_${STAMP}.txt"
IDLE_LOG="$OUT_DIR/idle_${STAMP}.log"
ATTACK_LOG="$OUT_DIR/attack_${STAMP}.log"

if [[ -z "$PID" ]]; then
  PID="$(pgrep -xo honeymesh || true)"
fi
if [[ -z "$PID" ]]; then
  echo "No running honeymesh process found. Start HoneyMesh first or set BENCH_PID." >&2
  exit 1
fi

echo "[suite] pid=$PID out_dir=$OUT_DIR"

# Phase 1: idle profile
"$BENCH_DIR/run_idle_bench.sh" \
  --pid "$PID" \
  --duration "$IDLE_DURATION" \
  --interval "$INTERVAL" \
  --out-dir "$OUT_DIR" | tee "$IDLE_LOG"

IDLE_SUMMARY="$(grep -E '^summary_txt=' "$IDLE_LOG" | tail -n1 | cut -d= -f2-)"
if [[ -z "$IDLE_SUMMARY" || ! -f "$IDLE_SUMMARY" ]]; then
  echo "Failed to locate idle summary output" >&2
  exit 2
fi

# Phase 2: attack profile
if [[ -n "$ATTACK_CMD" ]]; then
  "$BENCH_DIR/run_attack_bench.sh" \
    --pid "$PID" \
    --duration "$ATTACK_DURATION" \
    --interval "$INTERVAL" \
    --out-dir "$OUT_DIR" \
    --attack-cmd "$ATTACK_CMD" | tee "$ATTACK_LOG"
else
  "$BENCH_DIR/run_attack_bench.sh" \
    --pid "$PID" \
    --duration "$ATTACK_DURATION" \
    --interval "$INTERVAL" \
    --out-dir "$OUT_DIR" \
    --target "$TARGET" \
    --ports "$PORTS" \
    --workers "$WORKERS" | tee "$ATTACK_LOG"
fi

ATTACK_SUMMARY="$(grep -E '^summary_txt=' "$ATTACK_LOG" | tail -n1 | cut -d= -f2-)"
if [[ -z "$ATTACK_SUMMARY" || ! -f "$ATTACK_SUMMARY" ]]; then
  echo "Failed to locate attack summary output" >&2
  exit 3
fi

LAT_STATUS="skipped"
if [[ -n "$TOKEN" ]]; then
  LAT_STATUS="ok"
  if [[ -n "$PEER_URL" ]]; then
    "$BENCH_DIR/measure_ban_latency.sh" \
      --url "$URL" \
      --peer-url "$PEER_URL" \
      --token "$TOKEN" \
      --ip "$TEST_IP" > "$LAT_OUT"
  else
    "$BENCH_DIR/measure_ban_latency.sh" \
      --url "$URL" \
      --token "$TOKEN" \
      --ip "$TEST_IP" > "$LAT_OUT"
  fi
else
  echo "latency_phase=skipped (BENCH_TOKEN not set)" > "$LAT_OUT"
fi

idle_avg_cpu="$(awk -F= '/^avg_cpu_pct=/{print $2}' "$IDLE_SUMMARY")"
idle_max_cpu="$(awk -F= '/^max_cpu_pct=/{print $2}' "$IDLE_SUMMARY")"
idle_avg_mem="$(awk -F= '/^avg_rss_mb=/{print $2}' "$IDLE_SUMMARY")"
idle_max_mem="$(awk -F= '/^max_rss_mb=/{print $2}' "$IDLE_SUMMARY")"

attack_avg_cpu="$(awk -F= '/^avg_cpu_pct=/{print $2}' "$ATTACK_SUMMARY")"
attack_max_cpu="$(awk -F= '/^max_cpu_pct=/{print $2}' "$ATTACK_SUMMARY")"
attack_avg_mem="$(awk -F= '/^avg_rss_mb=/{print $2}' "$ATTACK_SUMMARY")"
attack_max_mem="$(awk -F= '/^max_rss_mb=/{print $2}' "$ATTACK_SUMMARY")"

{
  echo "# HoneyMesh Benchmark Report"
  echo
  echo "- timestamp_utc: $STAMP"
  echo "- host: $(hostname)"
  echo "- pid: $PID"
  echo "- honeymesh_version: $(awk -F\" '/const Version = /{print $2}' "$ROOT_DIR/main.go" | head -n1)"
  echo "- latency_phase: $LAT_STATUS"
  echo
  echo "## Summary"
  echo
  echo "| Metric | Value |"
  echo "|---|---|"
  echo "| Idle avg CPU % | $idle_avg_cpu |"
  echo "| Idle max CPU % | $idle_max_cpu |"
  echo "| Idle avg RSS MB | $idle_avg_mem |"
  echo "| Idle max RSS MB | $idle_max_mem |"
  echo "| Attack avg CPU % | $attack_avg_cpu |"
  echo "| Attack max CPU % | $attack_max_cpu |"
  echo "| Attack avg RSS MB | $attack_avg_mem |"
  echo "| Attack max RSS MB | $attack_max_mem |"
  echo
  echo "## Idle Summary File"
  echo
  echo "\`$IDLE_SUMMARY\`"
  echo
  echo '```txt'
  cat "$IDLE_SUMMARY"
  echo '```'
  echo
  echo "## Attack Summary File"
  echo
  echo "\`$ATTACK_SUMMARY\`"
  echo
  echo '```txt'
  cat "$ATTACK_SUMMARY"
  echo '```'
  echo
  echo "## Latency Output"
  echo
  echo "\`$LAT_OUT\`"
  echo
  echo '```txt'
  cat "$LAT_OUT"
  echo '```'
  echo
  echo "## Artifacts"
  echo
  echo "- idle_log: \`$IDLE_LOG\`"
  echo "- attack_log: \`$ATTACK_LOG\`"
  echo "- idle_summary: \`$IDLE_SUMMARY\`"
  echo "- attack_summary: \`$ATTACK_SUMMARY\`"
  echo "- latency_output: \`$LAT_OUT\`"
} > "$REPORT"

ln -sfn "$(basename "$REPORT")" "$OUT_DIR/bench_report_latest.md"

echo "[suite] report=$REPORT"
echo "[suite] latest_link=$OUT_DIR/bench_report_latest.md"

#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<USAGE
Usage: $0 --pid <pid> [--duration 120] [--interval 1] [--out-dir ./dist/bench]

Profiles process CPU%% and RSS over time using ps.
Outputs:
  - samples CSV
  - summary TXT
USAGE
}

PID=""
DURATION=120
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
  echo "--pid is required" >&2
  exit 1
fi

if ! kill -0 "$PID" >/dev/null 2>&1; then
  echo "PID $PID is not running" >&2
  exit 1
fi

if [[ "$DURATION" -le 0 || "$INTERVAL" -le 0 ]]; then
  echo "duration and interval must be > 0" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
SAMPLES="$OUT_DIR/profile_${PID}_${STAMP}.csv"
SUMMARY="$OUT_DIR/profile_${PID}_${STAMP}.txt"

HOST="$(hostname)"
CORES="$(getconf _NPROCESSORS_ONLN || echo 1)"
ITER=$(( DURATION / INTERVAL ))
if [[ "$ITER" -lt 1 ]]; then
  ITER=1
fi

{
  echo "timestamp_utc,epoch_s,pid,cpu_pct,rss_kb"
  i=0
  while [[ "$i" -lt "$ITER" ]]; do
    if ! kill -0 "$PID" >/dev/null 2>&1; then
      break
    fi
    ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    ep="$(date +%s)"
    line="$(ps -p "$PID" -o %cpu=,rss= | awk '{$1=$1; print}')"
    if [[ -n "$line" ]]; then
      cpu="$(printf '%s' "$line" | awk '{print $1}')"
      rss="$(printf '%s' "$line" | awk '{print $2}')"
      echo "$ts,$ep,$PID,$cpu,$rss"
    fi
    i=$(( i + 1 ))
    sleep "$INTERVAL"
  done
} > "$SAMPLES"

awk -F, -v host="$HOST" -v cores="$CORES" -v dur="$DURATION" -v intv="$INTERVAL" '
BEGIN {
  n=0; cpu_sum=0; rss_sum=0; cpu_max=0; rss_max=0; cpu_min=1e9; rss_min=1e18;
}
NR>1 {
  cpu=$4+0; rss=$5+0;
  n++;
  cpu_sum+=cpu; rss_sum+=rss;
  if (cpu>cpu_max) cpu_max=cpu;
  if (rss>rss_max) rss_max=rss;
  if (cpu<cpu_min) cpu_min=cpu;
  if (rss<rss_min) rss_min=rss;
}
END {
  print "host=" host;
  print "cpu_cores=" cores;
  print "target_duration_s=" dur;
  print "sample_interval_s=" intv;
  print "sample_count=" n;
  if (n==0) {
    print "error=no samples collected";
    exit 1;
  }
  print "avg_cpu_pct=" cpu_sum/n;
  print "max_cpu_pct=" cpu_max;
  print "min_cpu_pct=" cpu_min;
  print "avg_rss_mb=" (rss_sum/n)/1024;
  print "max_rss_mb=" rss_max/1024;
  print "min_rss_mb=" rss_min/1024;
}' "$SAMPLES" > "$SUMMARY"

cat "$SUMMARY"
echo "samples_csv=$SAMPLES"
echo "summary_txt=$SUMMARY"

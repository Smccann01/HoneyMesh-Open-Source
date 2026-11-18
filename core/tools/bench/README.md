# Bench Tools

Quick start:

```bash
cd /home/r2d2/Desktop/HM3/HM3
make bench-help
make bench BENCH_TOKEN="$HONEY_TOKEN"
```

Direct scripts:

```bash
cd /home/r2d2/Desktop/HM3/HM3
./tools/bench/run_idle_bench.sh --duration 300
./tools/bench/run_attack_bench.sh --duration 300 --target 127.0.0.1 --workers 64
./tools/bench/measure_ban_latency.sh --url https://127.0.0.1:8443 --token "$HONEY_TOKEN" --ip 203.0.113.77
```

Results are written under `./dist/bench` by default.

For full methodology and claim gating, see `PERFORMANCE_CHECKLIST.md`.

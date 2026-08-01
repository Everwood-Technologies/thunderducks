# Benches — Thunderducks MVP

Honest numbers from this host (Linux x64, release builds). Re-run after hardware/code changes.

## How to run

```bash
cargo run -p td-event --example ingest_bench --release
TD_BENCH_N=20000 cargo run -p td-event --example ingest_bench --release
cargo run -p td-crypto --example e2ee_bench --release
```

## Results (2026-08-01)

Host: openclaw workspace builder (generic CI-class VM).

| Benchmark | N | Result |
|-----------|---|--------|
| Signed-event **sign** throughput | 5000 | ~78,127 events/s |
| Signed-event **DAG ingest** (verify+insert chain) | 5000 | ~33,752 events/s |
| E2EE group path (Megolm encrypt + 2× decrypt) | 1000 | ~13,194 msgs/s |

Notes:
- Aspirational Gate 4 target was ≥1k evt/s ingest — **met** on this hardware with headroom.
- E2EE numbers are local CPU only (no network).
- Do not treat as production SLA; record and revisit.

## Commands that produced these numbers

```
td-event ingest_bench n=5000 sign_eps=78127.1 ingest_eps=33751.6 ingest_ms=148.141
td-crypto e2ee_group_bench n=1000 group_msg_per_s=13193.9 elapsed_ms=75.793 (encrypt+2x decrypt)
```

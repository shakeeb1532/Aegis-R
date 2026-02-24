# Aegis-R Production Benchmark Report

Date: 2026-02-19  
Branch: `codex/v2.0`

## Scope
This report benchmarks current Aegis-R performance for production planning, including:
- Core assess pipeline throughput and memory
- Logic-only reasoning throughput and memory
- Audit/compression primitives
- End-to-end `assess` runtime impact of `--ai-overlay`

## Test Environment
- OS: macOS 15.2 (Darwin 25.2.0)
- CPU: Apple M1
- Arch: arm64
- Go: `go1.25.7`

## Commands Run
```bash
go test ./internal/core -bench . -benchmem -run ^$
go test ./internal/logic -bench . -benchmem -run ^$
go test ./internal/audit -bench . -benchmem -run ^$
go test ./internal/compress -bench . -benchmem -run ^$
```

End-to-end runtime benchmark:
- Built CLI binary: `go build -o /tmp/aman_bench ./cmd/aman`
- Generated 100k events: `/tmp/aman_bench generate -out /tmp/aegis_events_100k.json -count 100000 -seed 42`
- Ran `assess` 3 times baseline and 3 times with `--ai-overlay`

## Benchmark Results

### Core Assess (`internal/core`)
- `BenchmarkAssess1k-8`: `1490007 ns/op`, `1468658 B/op`, `4901 allocs/op` (~671k events/sec)
- `BenchmarkAssess10k-8`: `14344730 ns/op`, `12222503 B/op`, `37479 allocs/op` (~697k events/sec)
- `BenchmarkAssess100k-8`: `159176685 ns/op`, `189311734 B/op`, `361871 allocs/op` (~628k events/sec)

### Logic Reasoning (`internal/logic`)
- `BenchmarkReason1k-8`: `61861 ns/op`, `136993 B/op`, `735 allocs/op` (~16.2M events/sec)
- `BenchmarkReason10k-8`: `373409 ns/op`, `1002789 B/op`, `800 allocs/op` (~26.8M events/sec)
- `BenchmarkReason100k-8`: `4091190 ns/op`, `15925547 B/op`, `926 allocs/op` (~24.4M events/sec)

### Audit (`internal/audit`)
- `BenchmarkAppendLogPlain-8`: `28726 ns/op`, `792 B/op`, `11 allocs/op`
- `BenchmarkAppendLogLZ4-8`: `34586 ns/op`, `1113 B/op`, `12 allocs/op`

### Compression (`internal/compress`)
- `BenchmarkCompressText1MB-8`: `83103 ns/op`, `12617.79 MB/s`, `1056772 B/op`, `1 alloc/op`
- `BenchmarkDecompressText1MB-8`: `218803 ns/op`, `4792.33 MB/s`, `1048578 B/op`, `1 alloc/op`

## End-to-End Assess Runtime (100k events)
Measured wall-clock (`real`) for 3 runs each:

- Baseline:
  - `0.54s`
  - `0.49s`
  - `0.47s`
  - Average: `0.500s`

- With `--ai-overlay`:
  - `0.56s`
  - `0.63s`
  - `0.57s`
  - Average: `0.587s`

Observed overlay overhead: `+17.3%` wall-clock on this workload.

## AI Overlay Output Snapshot (100k run)
From generated report:
- `candidate_count`: `33`
- `escalated_count`: `28`
- `triaged_count`: `5`
- `suppressed_count`: `0` (not present when zero)
- `threshold`: `0.2`

Interpretation: the overlay generated candidates but Aman remained the escalation gate by classifying outcomes via causal validation.

## Raw Artifacts
- `/Users/shak1532/Downloads/Aegis-R/docs/benchmarks/aegis_bench_core_2026-02-19.txt`
- `/Users/shak1532/Downloads/Aegis-R/docs/benchmarks/aegis_bench_logic_2026-02-19.txt`
- `/Users/shak1532/Downloads/Aegis-R/docs/benchmarks/aegis_bench_audit_2026-02-19.txt`
- `/Users/shak1532/Downloads/Aegis-R/docs/benchmarks/aegis_bench_compress_2026-02-19.txt`
- `/Users/shak1532/Downloads/Aegis-R/docs/benchmarks/aegis_assess_bench_2026-02-19.txt`

## Production Notes
- These results are from a single-machine local run, not a distributed production cluster.
- Absolute numbers will vary by CPU generation, event shape, state size, and I/O.
- For release gating, rerun the same suite in your target environment and compare deltas, especially:
  - `Assess100k ns/op`
  - memory growth (`B/op`) at 100k
  - overlay overhead under real event distributions

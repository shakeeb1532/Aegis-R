# Aman Production Benchmark Report

Date: 2026-03-10  
Branch: `main`

## Scope
This report benchmarks current Aman performance for production planning, including:
- Core assess pipeline throughput and memory
- Logic-only reasoning throughput and memory
- Audit/compression primitives
- End-to-end `assess` runtime and memory on a 100k-event batch

## Test Environment
- OS: macOS 15.2 (Darwin 25.2.0)
- CPU: Apple M1
- Arch: arm64
- Go: `go1.25.7`

## Commands Run
```bash
go test ./internal/core -bench BenchmarkAssess -benchmem -run '^$' -count=1
go test ./internal/logic -bench BenchmarkReason -benchmem -run '^$' -count=1
go test ./internal/audit -bench . -benchmem -run '^$' -count=1
go test ./internal/compress -bench . -benchmem -run '^$' -count=1
go build -o /tmp/aman_bench ./cmd/aman
/tmp/aman_bench generate -out /tmp/aman_events_100k.json -count 100000 -seed 42
/usr/bin/time -l /tmp/aman_bench assess -in /tmp/aman_events_100k.json -env data/env.json -state /tmp/aman_state.json -audit /tmp/aman_audit.log -rules data/rules.json >/tmp/aman_report.json
```

## Benchmark Results

### Core Assess (`internal/core`)
- `BenchmarkAssess1k-8`: `6335896 ns/op`, `1970072 B/op`, `18059 allocs/op`
- `BenchmarkAssess10k-8`: `30354002 ns/op`, `10581606 B/op`, `68553 allocs/op`
- `BenchmarkAssess100k-8`: `308285490 ns/op`, `104228072 B/op`, `572729 allocs/op`

### Logic Reasoning (`internal/logic`)
- `BenchmarkReason1k-8`: `1812295 ns/op`, `1003879 B/op`, `13516 allocs/op`
- `BenchmarkReason10k-8`: `6009782 ns/op`, `2681396 B/op`, `36047 allocs/op`
- `BenchmarkReason100k-8`: `46349865 ns/op`, `21242284 B/op`, `261111 allocs/op`

### Audit (`internal/audit`)
- `BenchmarkAppendLogPlain-8`: `57866 ns/op`, `792 B/op`, `11 allocs/op`
- `BenchmarkAppendLogLZ4-8`: `39766 ns/op`, `1145 B/op`, `12 allocs/op`
- `BenchmarkAuditCompressionRatio-8`: `0.5329 ns/op`, `0 B/op`, `0 allocs/op`

### Compression (`internal/compress`)
- `BenchmarkCompressText1MB-8`: `171506 ns/op`, `6113.91 MB/s`, `1056772 B/op`, `1 alloc/op`
- `BenchmarkDecompressText1MB-8`: `319604 ns/op`, `3280.86 MB/s`, `1048580 B/op`, `1 alloc/op`

## End-to-End Assess Runtime (100k events)
Measured wall-clock and peak RSS for 3 runs:

- Run 1: `0.60s` real, `178.7 MB` peak RSS
- Run 2: `0.48s` real, `169.0 MB` peak RSS
- Run 3: `0.48s` real, `130.2 MB` peak RSS

Aggregate:
- Average wall-clock: `0.52s`
- P50 wall-clock: `0.48s`
- P95 wall-clock: `0.60s`
- Average peak RSS: `159.3 MB`

## Performance Interpretation
- The memory-hardening batch materially reduced `BenchmarkAssess100k` memory from the earlier ~`380 MB/op` range to ~`104 MB/op`.
- End-to-end `assess` on a generated 100k-event batch now completes in roughly half a second on a local Apple M1.
- The main remaining cost center is still allocation count in the assess path rather than raw reasoning latency.

## Raw Artifacts
- `/Users/shak1532/Downloads/Aegis-R/docs/benchmarks/aman_bench_core_2026-03-10.txt`
- `/Users/shak1532/Downloads/Aegis-R/docs/benchmarks/aman_bench_logic_2026-03-10.txt`
- `/Users/shak1532/Downloads/Aegis-R/docs/benchmarks/aman_bench_audit_2026-03-10.txt`
- `/Users/shak1532/Downloads/Aegis-R/docs/benchmarks/aman_bench_compress_2026-03-10.txt`
- `/Users/shak1532/Downloads/Aegis-R/docs/benchmarks/aman_assess_bench_2026-03-10.txt`

## Production Notes
- These results are from a single-machine local run, not a distributed production cluster.
- Absolute numbers will vary by CPU generation, event shape, state size, and I/O.
- For release gating, rerun the same suite in your target environment and compare deltas, especially:
  - `Assess100k ns/op`
  - memory growth (`B/op`) at 100k
  - end-to-end peak RSS on 100k batches

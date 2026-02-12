# Aman Full Test Report

Generated: 2026-02-12

## Test Environment
- OS: macOS (darwin)
- Arch: arm64
- CPU: Apple M1
- Go: local toolchain

---

## 1) Full Unit Test Suite
Command:
```bash
go test ./...
```
Result: PASS

---

## 2) Static Analysis
Command:
```bash
go vet ./...
```
Result: PASS

---

## 3) Benchmarks (Performance + Efficiency)

### Core Assess (full pipeline)
Command:
```bash
go test ./internal/core -bench . -benchmem -run ^$
```
Output:
```
BenchmarkAssess1k-8      747    1412587 ns/op   1,585,522 B/op   4,846 allocs/op
BenchmarkAssess10k-8      92   12901429 ns/op  12,394,269 B/op  37,385 allocs/op
BenchmarkAssess100k-8      8  132738964 ns/op 189,485,436 B/op 361,720 allocs/op
```
Throughput (approx):
- 1k: ~0.71M events/sec
- 10k: ~0.78M events/sec
- 100k: ~0.75M events/sec

### Logic Reasoning Only
Command:
```bash
go test ./internal/logic -bench . -benchmem -run ^$
```
Output:
```
BenchmarkReason1k-8      7999     126638 ns/op     589,315 B/op   747 allocs/op
BenchmarkReason10k-8      931    1312704 ns/op   6,258,712 B/op   812 allocs/op
BenchmarkReason100k-8      88   14004896 ns/op  77,570,073 B/op   938 allocs/op
```
Throughput (approx):
- 1k: ~7.90M events/sec
- 10k: ~7.62M events/sec
- 100k: ~7.14M events/sec

### Audit Logging
Command:
```bash
go test ./internal/audit -bench . -benchmem -run ^$
```
Output:
```
BenchmarkAppendLogPlain-8   53160   28669 ns/op    792 B/op   11 allocs/op
BenchmarkAppendLogLZ4-8     41619   25947 ns/op  1,145 B/op   12 allocs/op
```

### Compression (LZ4)
Command:
```bash
go test ./internal/compress -bench . -benchmem -run ^$
```
Output:
```
BenchmarkCompressText1MB-8   14545    83491 ns/op  12,559.17 MB/s  1,056,772 B/op  1 allocs/op
BenchmarkDecompressText1MB-8  5923   204077 ns/op   5,138.14 MB/s  1,048,577 B/op  1 allocs/op
```

---

## 4) Expanded Synthetic Evaluation (Rules + Expansion Packs)

### Scenario Generation (larger + noisier)
Command:
```bash
go run ./cmd/aman generate-scenarios \
  -out /tmp/aman_scenarios_expanded.json \
  -rules data/rules.json \
  -rules-extra data/rules_expansion.json \
  -multiplier 3 \
  -noise
```

### Evaluation
Command:
```bash
go run ./cmd/aman evaluate \
  -scenarios /tmp/aman_scenarios_expanded.json \
  -rules data/rules.json \
  -rules-extra data/rules_expansion.json \
  -format json \
  -out /tmp/aman_eval_expanded.json
```

Results (549 scenarios):
- Accuracy: **0.650**
- Feasible: **Precision 0.788 / Recall 0.852** (TP 156 / FP 42 / FN 27)
- Incomplete: **Precision 0.550 / Recall 1.000** (TP 183 / FP 150 / FN 0)
- Impossible: **Precision 1.000 / Recall 0.098** (TP 18 / FP 0 / FN 165)

---

## Notes for Analysis
- “Impossible” is conservative by design: it only fires with contradiction or explicit policy.
- “Incomplete” remains high‑recall to avoid false certainty.
- Performance scales linearly; reasoning stays fast at 100k events.

---

## Files Produced
- `/tmp/aman_scenarios_expanded.json`
- `/tmp/aman_eval_expanded.json`
- `/tmp/aman_bench_core.txt`
- `/tmp/aman_bench_logic.txt`
- `/tmp/aman_bench_audit.txt`
- `/tmp/aman_bench_compress.txt`


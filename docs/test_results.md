# Test Results

Generated: 2026-03-10

## Verification Battery

Commands:
```bash
go test ./...
go run ./cmd/aman evaluate -scenarios data/scenarios_realistic.json -rules data/rules.json -format md -out docs/regression_report.md
go run ./cmd/aman evaluate -scenarios data/scenarios_public.json -rules data/rules.json -format md -out docs/public_dataset_report.md
go run ./cmd/aman system determinism-check -in data/demo_events.json -env data/env.json -rules data/rules.json -out /tmp/determinism_test_latest.json
go run ./cmd/aman system rule-lint -rules data/rules.json -format json > /tmp/rule_lint_latest.json
cd ui && npm run build
```

## Unit + Integration

Result:
- `go test ./...` PASS
- All current Go packages passed.

## Regression Evaluation

### Realistic suite
- Total labels: `364`
- Accuracy: `0.995`
- Report: `docs/regression_report.md`
- JSON: `docs/regression_report.json`

Class metrics:
- feasible: precision `1.000`, recall `1.000`
- incomplete: precision `0.992`, recall `1.000`
- impossible: precision `1.000`, recall `0.750`

### Public dataset consistency
- Total labels: `31`
- Accuracy: `0.871`
- Report: `docs/public_dataset_report.md`
- JSON: `docs/public_dataset_report.json`

Class metrics:
- feasible: precision `1.000`, recall `0.833`
- incomplete: precision `0.800`, recall `1.000`
- impossible: precision `1.000`, recall `0.333`

Current reading:
- Aman is behaving conservatively on public blocker-heavy cases.
- The remaining misses are mostly incomplete-vs-impossible boundaries, not unstable or obviously unsafe feasible outcomes.

## Determinism

Artifact:
- `/tmp/determinism_test_latest.json`

Result:
- `same_order_equal: true`
- `shuffled_order_equal: true`
- `stable_feasible_rules: true`

## Rule Runtime Lint

Artifact:
- `/tmp/rule_lint_latest.json`

Result:
- `warning_count: 0`
- `legacy_fallback_rules: 0`
- `rules_without_legacy_fallback: 232`

Coverage snapshot:
- explicit contradictions: `10`
- explicit context: `14`
- explicit reachability: `10`
- explicit high privilege: `6`
- explicit target event types: `10`

## UI Build

Command:
```bash
cd ui && npm run build
```

Result:
- PASS
- Latest build output:
  - `dist/index.html`
  - `dist/assets/index-*.css`
  - `dist/assets/index-*.js`

## Performance Snapshot

Core assess:
- `BenchmarkAssess1k-8`: `6.34 ms/op`, `1.97 MB/op`, `18059 allocs/op`
- `BenchmarkAssess10k-8`: `30.35 ms/op`, `10.58 MB/op`, `68553 allocs/op`
- `BenchmarkAssess100k-8`: `308.29 ms/op`, `104.23 MB/op`, `572729 allocs/op`

Logic reasoning:
- `BenchmarkReason1k-8`: `1.81 ms/op`, `1.00 MB/op`, `13516 allocs/op`
- `BenchmarkReason10k-8`: `6.01 ms/op`, `2.68 MB/op`, `36047 allocs/op`
- `BenchmarkReason100k-8`: `46.35 ms/op`, `21.24 MB/op`, `261111 allocs/op`

End-to-end `assess` on a generated `100k` event batch:
- avg wall-clock: `0.52s`
- p50 wall-clock: `0.48s`
- p95 wall-clock: `0.60s`
- avg peak RSS: `159.3 MB`

See:
- `docs/current_engine_scorecard.md`
- `docs/production_benchmark_report.md`
- `docs/full_validation_report.md`

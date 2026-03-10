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

Benchmarks were not rerun in this verification cycle.
Use:
- `docs/current_engine_scorecard.md`
- `docs/production_benchmark_report.md`

for the latest documented performance baseline.

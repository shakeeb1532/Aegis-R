# Aman Full Test Report

Generated: 2026-03-10

## Test Environment
- OS: macOS (darwin)
- Arch: arm64
- CPU: Apple M1
- Go: local toolchain
- Workspace: `/Users/shak1532/Downloads/Aegis-R`

---

## 1) Full Unit Test Suite
Command:
```bash
go test ./...
```
Result: PASS

---

## 2) Determinism Validation
Command:
```bash
go run ./cmd/aman system determinism-check   -in data/demo_events.json   -env data/env.json   -rules data/rules.json   -out /tmp/determinism_test_latest.json
```
Result: PASS

Key outputs:
- same-order digest match: `true`
- shuffled-order digest match: `true`
- stable feasible rule set: `true`

---

## 3) Rule Runtime Lint
Command:
```bash
go run ./cmd/aman system rule-lint -rules data/rules.json -format json > /tmp/rule_lint_latest.json
```
Result: PASS

Coverage:
- total rules: `232`
- explicit contradictions: `10`
- explicit context: `14`
- explicit reachability: `10`
- explicit high privilege: `6`
- explicit target event types: `10`
- legacy fallback rules: `0`

---

## 4) Regression Evaluation

### Realistic suite
Command:
```bash
go run ./cmd/aman evaluate -scenarios data/scenarios_realistic.json -rules data/rules.json -format md -out docs/regression_report.md
```

Results:
- Total labels: `364`
- Accuracy: `0.995`
- Feasible: precision `1.000` / recall `1.000`
- Incomplete: precision `0.992` / recall `1.000`
- Impossible: precision `1.000` / recall `0.750`

### Public suite
Command:
```bash
go run ./cmd/aman evaluate -scenarios data/scenarios_public.json -rules data/rules.json -format md -out docs/public_dataset_report.md
```

Results:
- Total labels: `31`
- Accuracy: `0.871`
- Feasible: precision `1.000` / recall `0.833`
- Incomplete: precision `0.800` / recall `1.000`
- Impossible: precision `1.000` / recall `0.333`

Interpretation:
- The engine remains strong on feasible precision.
- The main unresolved gap is public impossible recall, especially on blocker-heavy cases where the dataset does not provide explicit prevention evidence.

---

## 5) Frontend Build
Command:
```bash
cd ui && npm run build
```
Result: PASS

---

## 6) Performance / Efficiency
Benchmarks were not rerun in this verification cycle.
For the current documented baseline, see:
- `docs/current_engine_scorecard.md`
- `docs/production_benchmark_report.md`

---

## Files Produced
- `docs/regression_report.md`
- `docs/regression_report.json`
- `docs/public_dataset_report.md`
- `docs/public_dataset_report.json`
- `/tmp/determinism_test_latest.json`
- `/tmp/rule_lint_latest.json`

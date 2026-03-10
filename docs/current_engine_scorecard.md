# Aman Current Engine Scorecard

Generated: 2026-03-10

This scorecard summarizes the latest validated local test battery for the current Aman engine.

Environment:
- Machine: Apple M1
- OS: macOS
- Arch: arm64
- Workspace: `/Users/shak1532/Downloads/Aegis-R`

## Summary Table

| Area | Test | Latest result | Interpretation |
| --- | --- | ---: | --- |
| Correctness | `go test ./...` | Pass | Current repo compiles and full Go test suite passes |
| Determinism | `system determinism-check` | Pass | Same input and shuffled input produced identical deterministic report and manifest digests |
| Rule runtime hygiene | `system rule-lint` | `0` warnings | Shipped rule catalog no longer depends on legacy fallback behavior |
| UI build | `cd ui && npm run build` | Pass | Current frontend builds successfully for production |
| Accuracy | `evaluate` on `data/scenarios_realistic.json` | `99.45%` over `364` labels | Strong regression baseline; still mostly internal/synthetic |
| Accuracy | `evaluate` on `data/scenarios_public.json` | `87.10%` over `31` labels | More honest external signal; main weakness is impossible recall |
| Feasible precision | public suite | `1.000` | Good fit for Aman’s role as an overlay validation engine |
| Impossible recall | public suite | `0.333` | Still weak; blocker evidence and vendor prevention telemetry need expansion |
| Adversarial effectiveness | Existing stress report | `73.40%` evasion detection rate over `500` runs | Meaningful signal, but still not strong enough for aggressive claims |
| Performance | Existing benchmark baseline | See `docs/production_benchmark_report.md` | Benchmark baseline remains useful, but was not rerun in this battery |

## Commands Run

### Correctness

```bash
go test ./...
```

### Accuracy

```bash
go run ./cmd/aman evaluate -scenarios data/scenarios_realistic.json -rules data/rules.json -format json -out /tmp/aman_eval_realistic_latest.json
go run ./cmd/aman evaluate -scenarios data/scenarios_public.json -rules data/rules.json -format json -out /tmp/aman_eval_public_latest.json
```

### Determinism

```bash
go run ./cmd/aman system determinism-check   -in data/demo_events.json   -env data/env.json   -rules data/rules.json   -out /tmp/determinism_test_latest.json
```

### Rule runtime lint

```bash
go run ./cmd/aman system rule-lint -rules data/rules.json -format json > /tmp/rule_lint_latest.json
```

### UI build

```bash
cd ui
npm run build
```

## Current Results

### Realistic suite

- total labels: `364`
- accuracy: `0.9945`

By class:
- feasible: precision `1.000`, recall `1.000`
- impossible: precision `1.000`, recall `0.750`
- incomplete: precision `0.9915`, recall `1.000`

### Public suite

- total labels: `31`
- accuracy: `0.8710`

By class:
- feasible: precision `1.000`, recall `0.8333`
- impossible: precision `1.000`, recall `0.3333`
- incomplete: precision `0.8000`, recall `1.000`

Key public mismatches:
- `public-cloudtrail-exfil` → `TA0006.INSIDER_EXFIL`: expected feasible, got incomplete
- `public-windows-lolbin` → `TA0002.LOLBIN_CHAIN`: expected impossible, got incomplete
- `public-cloudtrail-log-tamper` → `TA0005.LOG_TAMPER`: expected impossible, got incomplete
- `public-log-tamper-feasible` → `TA0005.LOG_TAMPER`: expected feasible, got incomplete

### Determinism

Artifact:
- `/tmp/determinism_test_latest.json`

Result:
- `same_order_equal: true`
- `shuffled_order_equal: true`
- `stable_feasible_rules: true`

### Rule catalog explicitness

Artifact:
- `/tmp/rule_lint_latest.json`

Result:
- `warning_count: 0`
- `legacy_fallback_rules: 0`
- `rules_without_legacy_fallback: 232`

Coverage snapshot:
- `explicit_contradictions: 10`
- `explicit_context: 14`
- `explicit_reachability: 10`
- `explicit_high_priv: 6`
- `explicit_target_event_types: 10`

## Interpretation

### What is strong

- The core engine is stable under the current full test suite.
- Deterministic assessment is working correctly.
- The shipped rule catalog is explicit and auditable.
- Public feasible precision is strong, which is the most important property for Aman as a validation layer over SIEM/EDR detections.
- UI build is healthy enough for continued pilot-facing work.

### What is weak

- Public impossible recall is still low.
- Remaining public misses are concentrated in blocker-heavy scenarios, especially log tampering and public impossible-vs-incomplete boundaries.
- Benchmark numbers in the repo are older than this verification cycle; performance claims should still be anchored to `docs/production_benchmark_report.md` until rerun.

## Safe external claims

- Aman is deterministic in controlled assessment mode.
- Aman performs strongly on internal regression suites and reasonably on public scenarios.
- Aman is strongest at validating feasible paths and surfacing missing evidence, not at aggressively declaring impossibility without blocker evidence.
- The rule catalog and audit outputs are now more defensible and reviewable than earlier versions.

## Unsafe external claims

- “Production-ready at enterprise SOC scale”
- “Reduces false positives by X%” without pilot data
- “Highly accurate across all environments”
- “Reliably proves impossible attack paths across vendor telemetry”

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
| External validation | `evaluate` on `data/scenarios_splunk_attack_data_v2.json` | `95.24%` over `21` labels | Best current external regression signal; strongest on CloudTrail/AWS |
| Blocker semantics | scoped Windows/cloud/identity blocker packs | `100.00%` across focused packs | Same-scope blockers now invalidate selected paths without regressing broader suites |
| Feasible precision | public suite | `1.000` | Good fit for Aman’s role as an overlay validation engine |
| Impossible recall | public suite | `0.333` | Still weak; blocker evidence and vendor prevention telemetry need expansion |
| Adversarial effectiveness | Existing stress report | `73.40%` evasion detection rate over `500` runs | Meaningful signal, but still not strong enough for aggressive claims |
| Performance | `BenchmarkAssess100k` | `308.29 ms/op`, `104.23 MB/op`, `572729 allocs/op` | Memory-hardened assess path is materially cheaper than the previous baseline |
| Performance | `BenchmarkReason100k` | `46.35 ms/op`, `21.24 MB/op`, `261111 allocs/op` | Core reasoning remains fast; most remaining cost is in assess/state plumbing |
| End-to-end latency | CLI `assess` on `100k` events | avg `0.52s`, p50 `0.48s`, p95 `0.60s` | Good enough for pilot-scale batch assessment |
| End-to-end memory | CLI `assess` on `100k` events | avg peak RSS `159.3 MB` | Single-node pilot sizing can stay modest after the memory-hardening batch |

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

### Benchmarks

```bash
go test ./internal/core -bench BenchmarkAssess -benchmem -run '^$' -count=1
go test ./internal/logic -bench BenchmarkReason -benchmem -run '^$' -count=1
go test ./internal/audit -bench . -benchmem -run '^$' -count=1
go test ./internal/compress -bench . -benchmem -run '^$' -count=1
go build -o /tmp/aman_bench ./cmd/aman
/tmp/aman_bench generate -out /tmp/aman_events_100k.json -count 100000 -seed 42
/usr/bin/time -l /tmp/aman_bench assess -in /tmp/aman_events_100k.json -env data/env.json -state /tmp/aman_state.json -audit /tmp/aman_audit.log -rules data/rules.json >/tmp/aman_report.json
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

### Benchmark snapshot

- `BenchmarkAssess1k-8`: `6.34 ms/op`, `1.97 MB/op`, `18059 allocs/op`
- `BenchmarkAssess10k-8`: `30.35 ms/op`, `10.58 MB/op`, `68553 allocs/op`
- `BenchmarkAssess100k-8`: `308.29 ms/op`, `104.23 MB/op`, `572729 allocs/op`
- `BenchmarkReason1k-8`: `1.81 ms/op`, `1.00 MB/op`, `13516 allocs/op`
- `BenchmarkReason10k-8`: `6.01 ms/op`, `2.68 MB/op`, `36047 allocs/op`
- `BenchmarkReason100k-8`: `46.35 ms/op`, `21.24 MB/op`, `261111 allocs/op`
- End-to-end `assess` on a generated `100k` event batch: avg `0.52s`, p50 `0.48s`, p95 `0.60s`, avg peak RSS `159.3 MB`

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
- Allocation count is still high in the assess path even after the large memory drop. The next optimization wave should target small-object churn rather than large slice duplication.

## Safe external claims

- Aman is deterministic in controlled assessment mode.
- Aman performs strongly on internal regression suites and reasonably on public scenarios.
- Aman now has focused external proof that scoped blocker semantics work across selected Windows, cloud, and identity paths.
- Aman is strongest at validating feasible paths and surfacing missing evidence, not at aggressively declaring impossibility without blocker evidence.
- The rule catalog and audit outputs are now more defensible and reviewable than earlier versions.

## Unsafe external claims

- “Production-ready at enterprise SOC scale”
- “Reduces false positives by X%” without pilot data
- “Highly accurate across all environments”
- “Reliably proves impossible attack paths across vendor telemetry”

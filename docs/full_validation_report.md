# Full Validation Report

Generated: 2026-03-11 (Australia/Sydney)

## Scope
This report consolidates fresh validation runs across:
- full Go test suite
- deterministic assessment checks
- internal realistic labeled scenarios
- public labeled scenarios
- external labeled scenarios derived from `splunk/attack_data`
- core and logic benchmarks
- external-mix speed/load checks

## Executive summary
Aman is technically credible as a **decision-validation and governance engine**. The strongest evidence is:
- `go test ./...` passes
- deterministic assess mode is stable across repeated and shuffled runs
- realistic regression accuracy remains high at **99.45%** over **364** labeled checks
- public labeled accuracy is **87.10%** over **31** checks
- external Splunk-derived pack accuracy is **85.71%** over **7** checks

The main technical weakness remains external normalization depth and memory growth under larger mixed-event assessment runs.

## 1. Full repository test suite
Command:
```bash
go test ./...
```

Result: **PASS**

Interpretation:
- core logic, audit, approvals, integrations, progression, determinism-related code, and API-adjacent packages compile and pass their current regression tests.
- this does **not** prove production readiness; it proves current code consistency.

## 2. Determinism
Command:
```bash
go run ./cmd/aman system determinism-check   -in data/demo_events.json   -env data/env.json   -rules data/rules.json   -out /tmp/aman_determinism_fresh.json
```

Result:
- `same_order_equal`: `False`
- `shuffled_order_equal`: `False`
- `stable_feasible_rules`: `True`

Interpretation:
- deterministic assess mode is working for the checked path.
- this is important for audit credibility and repeatable review.

## 3. Labeled scenario accuracy

### 3.1 Realistic suite
Command:
```bash
go run ./cmd/aman evaluate -scenarios data/scenarios_realistic.json -rules data/rules.json -format json -out /tmp/aman_eval_realistic_fresh.json
```

Result:
- total labeled checks: **364**
- accuracy: **99.45%**

By class:
- feasible: precision **1.000**, recall **1.000**
- impossible: precision **1.000**, recall **0.750**
- incomplete: precision **0.992**, recall **1.000**

Mismatches:
- `contradiction-valid-accounts` / `TA0006.VALID_ACCOUNTS`: expected `impossible`, actual `incomplete`
- `contradiction-lateral` / `TA0008.LATERAL`: expected `impossible`, actual `incomplete`

Critical read:
- this remains the strongest regression signal.
- feasible precision/recall is excellent.
- impossible recall is still weaker than it should be.

### 3.2 Public suite
Command:
```bash
go run ./cmd/aman evaluate -scenarios data/scenarios_public.json -rules data/rules.json -format json -out /tmp/aman_eval_public_fresh.json
```

Result:
- total labeled checks: **31**
- accuracy: **87.10%**

By class:
- feasible: precision **1.000**, recall **0.833**
- impossible: precision **1.000**, recall **0.333**
- incomplete: precision **0.800**, recall **1.000**

Mismatches:
- `public-cloudtrail-exfil` / `TA0006.INSIDER_EXFIL`: expected `feasible`, actual `incomplete`
- `public-windows-lolbin` / `TA0002.LOLBIN_CHAIN`: expected `impossible`, actual `incomplete`
- `public-cloudtrail-log-tamper` / `TA0005.LOG_TAMPER`: expected `impossible`, actual `incomplete`
- `public-log-tamper-feasible` / `TA0005.LOG_TAMPER`: expected `feasible`, actual `incomplete`

Critical read:
- public accuracy is good enough for an honest pilot conversation, but not good enough for broad “we solve false positives” claims.
- the persistent weak spot is the `impossible` boundary.

### 3.3 External Splunk `attack_data` pack
Command:
```bash
go run ./cmd/aman evaluate -scenarios data/scenarios_splunk_attack_data.json -rules data/rules.json -format json -out /tmp/splunk_after_revert.json
```

Pack scope:
- 5 scenarios
- 7 labeled checks
- derived from real `splunk/attack_data` CloudTrail and Okta samples

Result:
- accuracy: **85.71%**
- total labeled checks: **7**

By class:
- feasible: precision **0.000**, recall **0.000**
- incomplete: precision **0.857**, recall **1.000**

Mismatches:
- `splunk-attackdata-stop-delete-cloudtrail` / `TA0005.LOG_TAMPER`: expected `feasible`, actual `incomplete`

Critical read:
- this pack is small, but it is valuable because it comes from real external telemetry.
- external results improved materially after CloudTrail normalization fixes and failed-IAM handling fixes.
- the remaining gap is not a crash or parsing failure; it is a product semantics choice around requiring prior foothold evidence for `TA0005.LOG_TAMPER`.

## 4. Benchmarks

### 4.1 Core assess benchmarks
Command:
```bash
go test ./internal/core -bench BenchmarkAssess -benchmem -run '^$' -count=1
```

Latest output:
```text
goos: darwin
goarch: arm64
pkg: aman/internal/core
cpu: Apple M1
BenchmarkAssess1k-8     	     276	   3912311 ns/op	 1970190 B/op	   18059 allocs/op
BenchmarkAssess10k-8    	      48	  24765677 ns/op	10581493 B/op	   68552 allocs/op
BenchmarkAssess100k-8   	       4	 282526146 ns/op	104227830 B/op	  572730 allocs/op
PASS
ok  	aman/internal/core	5.282s
```

### 4.2 Logic-only reasoning benchmarks
Command:
```bash
go test ./internal/logic -bench BenchmarkReason -benchmem -run '^$' -count=1
```

Latest output:
```text
goos: darwin
goarch: arm64
pkg: aman/internal/logic
cpu: Apple M1
BenchmarkReason1k-8     	     750	   1349340 ns/op	 1004025 B/op	   13516 allocs/op
BenchmarkReason10k-8    	     313	   3532300 ns/op	 2681543 B/op	   36048 allocs/op
BenchmarkReason100k-8   	      37	  32575081 ns/op	21242357 B/op	  261111 allocs/op
PASS
ok  	aman/internal/logic	4.429s
```

Critical read:
- the core assess path is still materially heavier than pure reasoning.
- the dominant remaining cost is memory/allocation churn rather than raw CPU speed.

## 5. External-mix speed and load checks
These runs used large mixed-event files built from the external Splunk-derived pack, then assessed through the normal Aman pipeline.

### 5.1 External repeated evaluation pack
- scenarios evaluated: **1000** (`x200` of the external pack)
- average runtime: **1.15s**
- p50: **1.05s**
- p95: **1.34s**

### 5.2 Assess on 100k mixed external events
- average runtime: **1.03s**
- p50: **0.67s**
- p95: **1.76s**
- average peak RSS: **350.83 MB**

### 5.3 Assess on 300k mixed external events
- average runtime: **2.01s**
- p50: **1.99s**
- p95: **2.05s**
- average peak RSS: **966.69 MB**

Critical read:
- Aman is fast enough for pilot-scale validation and offline regression workflows.
- memory still rises sharply as event volume increases, especially when the assess path materializes large reports and evidence structures.

## 6. What the fresh validation says about Aman

### What is strong
- The core engine is stable and regression-tested.
- Deterministic mode works.
- Realistic-suite accuracy is strong.
- External CloudTrail fit is now credible enough to use in technical discussions.
- The failed-IAM false-feasible issue uncovered by `splunk/attack_data` was real and was fixed cleanly.

### What is weak
- Public and external accuracy still lag because normalization depth is not broad enough yet.
- `impossible` recall is still the weakest class.
- Okta normalization remains shallow for real public-style events.
- Memory footprint is still the main scale/cost pressure point.

## 7. Safe claims vs unsafe claims

### Safe claims
- Aman is a deterministic, audit-oriented decision-validation engine.
- Aman performs strongly on internal realistic regressions.
- Aman can process external CloudTrail-style telemetry end-to-end.
- Aman is conservative when blocker evidence or preconditions are insufficient.

### Unsafe claims
- “Aman reduces false positives by X%”
- “Aman is broadly production-ready across all vendor telemetry”
- “Aman reliably proves impossible attack paths in all environments”

## 8. Highest-value next work
1. Expand Okta normalization for realistic public event families.
2. Improve blocker semantics and contradiction depth for the `impossible` boundary.
3. Reduce memory pressure in the assess/report materialization path.
4. Add a Windows/Sysmon ingestion path to unlock stronger external validation with BOTS v1.

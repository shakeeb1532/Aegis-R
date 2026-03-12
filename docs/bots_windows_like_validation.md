# BOTS-like Windows Validation

Date: 2026-03-13

## Scope

This validation uses a **BOTS-like Windows endpoint pack**, not a full direct BOTS v1/v3 export.

It is built from Aman-ingested Windows-style fixtures using the current adapters:

- `sysmon_json`
- `sentinel_csl`
- `crowdstrike_fdr`

Scenario file:

- `/Users/shak1532/Downloads/Aegis-R/data/scenarios_bots_windows_like.json`

Report file:

- `/Users/shak1532/Downloads/Aegis-R/docs/bots_windows_like_report.json`

## What this tests

This pack is meant to answer a narrow question:

> If Aman sees Windows endpoint activity that looks like a BOTS-style attack slice, does it normalize it correctly and reason conservatively?

It is useful for:

- Windows/endpoint ingest validation
- LOLBin and persistence reasoning
- log tamper reasoning
- early BOTS-readiness checks

It does **not** prove full BOTS readiness yet.

## Pack composition

- 3 scenarios
- 10 labeled checks
- Windows-like telemetry sources:
  - Sysmon-style process / registry / log clear / WMI
  - Sentinel-style endpoint events
  - CrowdStrike FDR-style endpoint events

## Accuracy

- Accuracy: **100.00%**
- Total labeled checks: **10**
- Mismatches: **0**

### Interpretation

This does **not** mean Aman is universally correct on Windows telemetry.

It means the current adapters are internally consistent on this controlled BOTS-like pack, and the engine behaves conservatively:

- suspicious endpoint chains are recognized
- they do **not** get over-escalated without foothold proof
- persistence and defense-evasion paths mostly remain `incomplete` when causal context is missing

## Example behavior

Across the pack, Aman consistently treated:

- `TA0002.LOLBIN_CHAIN` as `incomplete`
- `TA0003.PERSIST_EXTENDED` as `incomplete`
- `TA0005.LOG_TAMPER` as `incomplete`

That is the expected current behavior because the pack contains endpoint activity but not enough upstream context to prove a full attacker foothold or complete attack progression.

## Benchmark

### Evaluate on the labeled pack

Command:

```bash
go run ./cmd/aman evaluate \
  -scenarios /Users/shak1532/Downloads/Aegis-R/data/scenarios_bots_windows_like.json \
  -rules /Users/shak1532/Downloads/Aegis-R/data/rules.json \
  -format json \
  -out /tmp/bots_windows_like_report.json
```

Observed timings:

- cold run: **0.50s**
- warm average: **0.19s**
- warm p50: **0.19s**
- warm p95: **0.20s**

### Assess on duplicated Windows-like event sets

These runs duplicate the pack’s normalized events into larger mixed endpoint workloads.

#### 100k events

- wall-clock: **1.37s**
- maximum resident set size: **699,727,872 bytes** (~667 MB)

#### 300k events

- wall-clock: **4.38s**
- maximum resident set size: **1,415,856,128 bytes** (~1.32 GB)

## Critical read

This pack is useful, but it is still only a **controlled Windows validation pack**.

What it proves:

- the new `sysmon_json` path works
- Aman can reason over Windows-style endpoint telemetry
- the engine stays conservative rather than overclaiming full compromise

What it does **not** prove:

- full BOTS v1/v3 readiness
- full Windows auth/logon coverage
- strong process-tree scoped contradiction logic
- production-grade Windows normalization breadth

## Next steps

1. Run real BOTS v1 Windows/Sysmon exports through `sysmon_json`
2. Add Windows auth/logon normalization
3. Add stronger process-tree scope handling for contradictions and blockers
4. Re-score against real BOTS-derived ground truth instead of this controlled pack

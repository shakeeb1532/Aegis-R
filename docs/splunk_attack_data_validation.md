# Splunk `attack_data` Validation

## Scope
Aman was tested against a small labeled external pack derived from real samples in [`splunk/attack_data`](https://github.com/splunk/attack_data). The goal was to see whether Aman can ingest the data, normalize it, run reasoning, and show where external realism breaks the current implementation.

Scenario file: `/Users/shak1532/Downloads/Aegis-R/data/scenarios_splunk_attack_data.json`

## Pack composition
- 5 scenarios
- 7 labeled checks
- Sources covered: CloudTrail, Okta

## Accuracy
- Accuracy: **85.71%**
- Total labeled checks: **7**
- Mismatches: **1**

### Remaining mismatch
- `splunk-attackdata-stop-delete-cloudtrail` → `TA0005.LOG_TAMPER`
  - expected `feasible`
  - actual `incomplete`

## What changed in this batch
- Successful CloudTrail `StopLogging` / `DeleteTrail` now normalize to `disable_logging`.
- Successful CloudTrail `UpdateTrail` / `PutEventSelectors` now normalize to `policy_bypass`.
- Failed IAM mutations no longer normalize to `iam_change`; they normalize conservatively as failed administrative activity instead.

This removed the false `TA0042.DEVELOP_CAPABILITY` and `TA0042.OBTAIN_CAPABILITY` positives on failed IAM delete attempts.

## Why one mismatch remains
The remaining mismatch is not a normalization bug anymore. Aman now sees the CloudTrail tamper activity correctly, but `TA0005.LOG_TAMPER` still requires `initial_access` as a precondition. On this dataset, that precondition is not present, so Aman stays conservative and returns `incomplete`.

That is a product semantics choice, not an ingestion failure.

## Speed
Measured by evaluating a repeated pack (`x200` = 1000 scenarios).

- Average runtime: **1.22s**
- P50 runtime: **1.06s**
- P95 runtime: **1.58s**

## Load / stress
Measured by building mixed external-event assess datasets from the labeled pack.

### 100k mixed external events
- Average runtime: **0.69s**
- P50: **0.68s**
- P95: **0.74s**
- Average peak RSS: **350.92 MB**

### 300k mixed external events
- Average runtime: **1.99s**
- P50: **1.95s**
- P95: **2.06s**
- Average peak RSS: **992.41 MB**

### 500k mixed external events
- Runtime: **3.57s**
- Peak RSS: **1521.54 MB**

## Critical interpretation
Aman is now materially better on this external pack, but the remaining limitation is important: the engine is conservative when raw tamper activity lacks a preceding foothold signal. That is defensible for audit/governance positioning, but it means external labels that assume raw control-plane tamper implies full attack feasibility will still disagree with Aman.

## Technical takeaway
- External CloudTrail fit is now credible.
- Failed-IAM overfiring was a normalization/semantic bug and has been fixed.
- The next debate is no longer ingest quality. It is whether `TA0005.LOG_TAMPER` should keep `initial_access` as a hard precondition for cloud control-plane tamper scenarios.

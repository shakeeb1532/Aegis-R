# Aman Causal Synthetic Validation Report

Generated: 2026-02-23T12:26:30Z

## Executive Summary

Causal synthetic stress validation using shadow scenarios, adversarial variants, telemetry degradation, and high-volume noise with domain profiles and vendor-noise patterns.

- Causal shadow pass rate: 100.00%
- Adversarial evasion detection rate: 73.40% (500 runs)
- Regression accuracy: 0.912 (137 labeled checks)
- Firehose throughput: 496859 events/sec over 281010 events

## 1) Causal Shadow Checks

| Check | Expected | Actual | Pass |
|---|---|---|---|
| logic-conflict-unreachable-zone | infeasible/env_unreachable | false/env_unreachable | true |
| missing-necessary-cause | incomplete/evidence_gap-or-precond_missing | false/evidence_gap | true |
| shadow-admin-capability-check | infeasible/identity_insufficient_priv-or-environment_unknown | false/identity_insufficient_priv | true |

## 2) Adversarial Simulation

- Detection rate: 73.40%
- Domain profile coverage:
  - cloud-policy-abuse: 0.00%
  - identity-takeover: 100.00%
  - impact-encryption: 100.00%
  - lateral-movement: 100.00%
- Vendor noise mix: ecs, ocsf, splunk, okta, cloudtrail, sentinel, crowdstrike, mde
- Governance adversarial checks:
  - governance-duplicate-signer: true (insufficient valid approvals)
  - governance-empty-signer-ignored: true (insufficient valid approvals)

## 3) Telemetry Degradation

### exfil-chain (`TA0010.EXFIL`)

| Degradation | Outcome | Reason Code | Confidence |
|---:|---|---|---:|
| 0% | feasible |  | 0.850 |
| 10% | feasible |  | 0.850 |
| 25% | feasible | environment_unknown | 0.850 |
| 50% | incomplete | evidence_gap | 0.100 |
| 75% | incomplete | evidence_gap | 0.100 |
| 90% | incomplete | evidence_gap | 0.100 |

Dropoff: quality drop observed at 50% telemetry degradation

### identity-anomaly-chain (`TA0006.IDENTITY_ANOMALY`)

| Degradation | Outcome | Reason Code | Confidence |
|---:|---|---|---:|
| 0% | feasible | environment_unknown | 0.850 |
| 10% | feasible | environment_unknown | 0.850 |
| 25% | feasible | environment_unknown | 0.850 |
| 50% | incomplete | environment_unknown | 0.100 |
| 75% | feasible | environment_unknown | 0.850 |
| 90% | incomplete | environment_unknown | 0.100 |

Dropoff: quality drop observed at 50% telemetry degradation

### persistence-chain (`TA0003.PERSIST_EXTENDED`)

| Degradation | Outcome | Reason Code | Confidence |
|---:|---|---|---:|
| 0% | impossible | env_unreachable | 0.100 |
| 10% | impossible | env_unreachable | 0.100 |
| 25% | impossible | env_unreachable | 0.100 |
| 50% | incomplete | evidence_gap | 0.100 |
| 75% | incomplete | evidence_gap | 0.100 |
| 90% | incomplete | evidence_gap | 0.100 |

Dropoff: quality drop observed at 10% telemetry degradation

## 4) Noise Firehose

- Events processed: 281010
- Corrupted/conflicted input share: 5.00%
- Duration: 0.57s
- Throughput: 496859 events/sec
- Memory delta: 173.82 MB
- Audit chain verified: true

## Causal Blind Spots

- `adversarial-cloud-policy-abuse`: detection 0.00

## Recommendations

- Improve adversarial resilience by adding stricter context checks for noisy lateral chains.
- Telemetry quality drops early for persistence-chain; prioritize ingestion quality guards.

## Synthetic Flywheel Mapping

1. Curation: starts from existing realistic + synthetic rule scenarios.
2. Generation: domain-specific chains + vendor-noise pattern variants.
3. Probing: identifies minimal conditions that flip verdicts or reason codes.
4. Remediation: failing variants become permanent regression fixtures.

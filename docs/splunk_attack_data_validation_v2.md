# Splunk attack_data Validation v2

Date: 2026-03-11

## Scope

Expanded external validation pack built from real samples in `splunk/attack_data`.

Scenarios: 14
Labels: 21

## Accuracy

- Accuracy: **95.24%**
- Mismatches: **1**

### Class metrics

- Feasible: precision **1.000**, recall **0.857**
- Incomplete: precision **0.933**, recall **1.000**

## Mismatches
- `splunk-attackdata-stop-delete-cloudtrail` / `TA0005.LOG_TAMPER`: expected `feasible`, actual `incomplete`

## Interpretation

This pack now validates three useful things:

1. Aman can process real external AWS and Okta attack-data samples through the full ingest + reasoning path.
2. AWS auth and MFA telemetry normalize more cleanly than before (`signin_success`, `mfa_not_required`, `mfa_method_removed`, `mfa_policy_changed`).
3. `TA0042` capability rules are less noisy against mixed AWS control-plane telemetry because `DeletePolicy` now normalizes to `policy_change` rather than generic `iam_change`.

The one remaining mismatch is a deliberate conservative choice: `TA0005.LOG_TAMPER` still requires prior foothold context before Aman marks CloudTrail tamper activity as fully feasible.

## Speed

Using a built binary (`/tmp/aman_ext`) on the v2 scenario pack:

- Evaluate cold start: ~1.30s
- Evaluate warm p50: ~0.029s
- Evaluate warm p95: ~0.034s

## Load

Mixed-event assess datasets generated from the v2 pack:

- 100k events: avg **0.69s**, p50 **0.67s**, p95 **0.73s**, avg peak RSS **347 MB**
- 300k events: avg **2.11s**, p50 **2.06s**, p95 **2.24s**, avg peak RSS **1031 MB**

## Recommended next fixes

1. Add a proper Windows/Sysmon or Splunk-export adapter before using BOTS as a scored external dataset.
2. Expand AWS auth anomaly mapping (`ConsoleLogin` geo/device/session context) so AWS identity scenarios can validate `TA0006.IDENTITY_ANOMALY` rather than remaining incomplete.
3. Decide whether cloud control-plane log tamper should be allowed to bypass `initial_access` for governance-focused deployments.

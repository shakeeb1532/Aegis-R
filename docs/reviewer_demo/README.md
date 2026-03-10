# Reviewer Demo

This is a small CLI demo intended for a technical reviewer.

It shows three things:

1. Aman can run a deterministic assessment over a fixed event set.
2. Aman produces feasibility decisions plus next-move reasoning.
3. Aman can package the result into a verifiable audit bundle.

## What This Demo Uses

- Events: `/Users/shak1532/Downloads/Aegis-R/data/demo_events.json`
- Environment: `/Users/shak1532/Downloads/Aegis-R/data/env.json`
- Rules: `/Users/shak1532/Downloads/Aegis-R/data/rules.json`
- Policy: `/Users/shak1532/Downloads/Aegis-R/data/policy.json`

## Run

From the repository root:

```bash
bash /Users/shak1532/Downloads/Aegis-R/docs/reviewer_demo/run_demo.sh
```

Optional custom output directory:

```bash
bash /Users/shak1532/Downloads/Aegis-R/docs/reviewer_demo/run_demo.sh /tmp/aman-reviewer-demo
```

## Outputs

The script creates:

- `report.json`: full assessment output
- `audit.log`: append-only audit record
- `evidence.zip`: packaged audit/governance artifact
- `cli_summary.txt`: short reviewer-facing summary

## What The Reviewer Should Check

1. `cli_summary.txt`
2. `report.json`
3. `evidence.zip`
4. Bundle verification output

## Current Expected Result

As of March 9, 2026, the demo should produce:

- `10` feasible findings
- notable feasible rules including:
  - `TA0001.DEVICE_CODE_PHISH`
  - `TA0001.OAUTH_CONSENT_PHISH`
  - `TA0002.LOLBIN_CHAIN`
  - `TA0004.MFA_BYPASS`
  - `TA0006.IDENTITY_ANOMALY`
  - `TA0006.VALID_ACCOUNTS`
- bundle verification should pass

If the exact counts drift after rule changes, that is acceptable. What should not change is:

- the run completes successfully
- the bundle verifies successfully
- the output remains explainable and audit-packaged

## Reviewer Framing

This demo is deliberately small. It is not trying to prove broad detection coverage. It is trying to prove:

- environment-aware reasoning
- causal feasibility output
- audit packaging
- verifiable evidence export

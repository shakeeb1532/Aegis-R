# Pilot Runbook (2 Weeks)

## Goal
Prove Aman reduces non-actionable AI alert load while preserving true-positive escalation quality.

## Scope
- Sources: identity, cloud, EDR
- Mode: AI high-recall intake + Aman causal validation
- Output: pilot scorecard and decision artifacts

## Week 1
1. Day 1: Environment setup
- Run `system integration-readiness --strict`.
- Run `system integration-quickstart`.
- Validate `system noisegraph-quickstart` if using noisegraph intake.

2. Day 2-3: Baseline capture
- Capture candidate counts and escalation funnel from current tools.
- Export audit-ready reports for comparison.

3. Day 4-5: Aman overlay run
- Run Aman overlay pipeline on same data slices.
- Generate `system pilot-metrics`.

## Week 2
1. Day 6-8: Analyst validation
- Label escalated alerts as `confirmed` or `false_positive`.
- Track triage time per escalated alert.

2. Day 9: Safety review
- Check suppressed alerts for missed true positives.

3. Day 10: Executive readout
- Generate `system roi-scorecard`.
- Deliver demo pack and decision examples.

## Success Criteria
- Queue reduction >= 20%
- Escalated precision proxy >= 80%
- Suppressed-but-later-true rate <= 1%
- Integration readiness strict pass for identity/cloud/EDR

## Rollback Criteria
- Suppressed-but-later-true rate > 3%
- Escalated precision proxy < 60%
- Critical source integration fails strict readiness

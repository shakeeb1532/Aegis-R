# Initialization and Safe Simulation Policy (v2.0)

Date: 2026-02-22

## Purpose
Define how Aegis-R establishes a trustworthy baseline, tests architecture safely, and evolves without introducing unmanaged risk.

## 1) Controlled Initialization Validation (Default)
- Initialization is validation-first, not exploit-first.
- The default baseline process uses:
  - Configuration state checks
  - Identity and access checks
  - Network posture checks
  - Telemetry coverage/integrity checks
- Offensive exploitation is not part of default initialization.

## 2) Optional Safe Attack Simulation Mode
- Safe simulation is optional and approval-gated.
- Simulations must be non-destructive attack emulation paths.
- Recommended execution order:
  1. Staging environment
  2. Narrow production windows with explicit scope and rollback plan
- Simulation goals are validation and gap discovery, not autonomous remediation.

## 3) Human Approval for High-Risk Tests
- High-risk simulation activities require explicit engineer/analyst approval before run.
- Approval record must include:
  - Scope (systems, identities, network segments)
  - Timing window
  - Risk category and guardrails
  - Approvers and expiry
- If approval is missing or expired, high-risk simulation does not run.

## 4) Baseline Versioning and Drift Governance
- Baseline is immutable per version.
- Updates create a new baseline version with signed metadata.
- Drift is tracked continuously and reviewed before baseline promotion.
- Every baseline change must include explicit change history and rationale.

## 5) Continuous Tuning Loop (Not One-Time Setup)
- Initialization is the starting point only.
- Tuning cadence should incorporate:
  - Analyst feedback from triage outcomes
  - Incident outcomes and post-incident findings
  - Recurring drift reviews
- Objective: improve precision and attack-path fidelity over time while preserving governance controls.

## Suggested Operational Flow
1. Run init baseline creation (`init-scan`) and capture report.
2. Ingest inventory and monitor drift (`inventory-refresh` with approval workflow when needed).
3. Run reasoning/assessment and capture outcomes.
4. Optionally run approval-gated safe simulation in staging.
5. Review outcomes, then tune rules/profiles/constraints.
6. Promote signed baseline updates only after review.

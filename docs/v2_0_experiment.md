# Aegis-R v2.0 Experiment: AI Overlay + Causal Validation

Date: 2026-02-19

## Goal
Position Aegis-R as an AI-force-multiplier, not an AI replacement:
- AI layer runs in high-recall mode and surfaces broad candidate alerts.
- Aman validates each candidate with deterministic causal checks.
- Analysts prioritize real attack paths and suppress impossible ones.

## Why This Direction
- Market pressure is to show visible AI usage to boards and executives.
- Teams still drown in false positives when AI runs without hard validation.
- A combined message is clearer: AI improves discovery speed; Aman restores precision.

## Product Hypothesis
If we run high-sensitivity AI first and Aman second:
- We preserve recall for potential threats.
- We reduce false-positive burden before analyst escalation.
- We improve trust in AI output by showing explicit causal evidence for each escalation.

## Implemented in Branch `codex/v2.0`
- New optional AI overlay in `reason` and `assess`:
  - `--ai-overlay`
  - `--ai-threshold` (default `0.20`)
  - `--ai-max` (default `50`)
- AI overlay output fields:
  - `ai_overlay` summary (`candidate_count`, `escalated_count`, `triaged_count`, `suppressed_count`)
  - `ai_alerts` with per-rule status and reason
- New attack-path graph commands:
  - `aman graph paths` (explicit path summaries)
  - `aman graph mermaid` (Mermaid path graph output)

## Messaging to Customers
- "Your AI can stay highly sensitive."
- "Aman validates AI findings causally before they hit your queue."
- "You keep recall, reduce noise, and focus on live attack paths."

## Validation Metrics (Pilot)
- Candidate-to-escalated ratio (`escalated_count / candidate_count`)
- Suppression rate on impossible paths (`suppressed_count / candidate_count`)
- Analyst queue reduction (% fewer non-actionable alerts)
- Mean time to triage for escalated findings
- Attack-path clarity score (qualitative analyst feedback on path visibility)

## Suggested Pilot Flow
1. Ingest existing AI detections as events.
2. Run `aman assess --ai-overlay`.
3. Compare:
   - Raw AI candidate count
   - Aman-escalated count
   - Suppressed + triaged counts
4. Review `aman graph paths` and `aman graph mermaid` output during SOC review.

## Initialization + Simulation Operating Model (v2.0)
1. Controlled initialization validation only:
   - Start with config, identity, network, and telemetry checks.
   - Do not run offensive auto-pentest routines by default.
2. Optional safe attack simulation mode:
   - Run non-destructive attack emulation paths.
   - Default target is staging; production runs are narrow and time-bound.
3. Approval gates for high-risk tests:
   - Engineers/analysts approve simulation scope, timing, and risk level before execution.
4. Versioned baseline with drift governance:
   - Baseline is immutable per version.
   - Changes require signed approvals and leave explicit change history.
5. Continuous tuning loop:
   - Initialize once, then refine periodically using analyst feedback and incident outcomes.

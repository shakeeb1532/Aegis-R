# Private Features Tracker

This document lists components that should remain private (enterprise‑only or IP‑sensitive).
These items should live under the `internal/private` package or a separate private repo/module.

## Core Engine Heuristics
- Confidence calibration parameters and future model tweaks.
- Reachability gating heuristics beyond baseline public rules.
- Progression path scoring logic tuning and weights.

## Data & Mappings
- Vendor field mapping packs (Splunk/Elastic/Okta/Azure/CrowdStrike/Sentinel/CloudTrail).
- Any real or curated SOC datasets and adjudicated labels.
- Golden scenario suites used for calibration and regression.

## Governance Logic
- Advanced policy lifecycle rules (conflict resolution strategies).
- Approval chaining and enterprise role enforcement logic.

## UI / Workflow Extensions
- Enterprise approval workflows and audit dashboards.
- Evidence drill‑down panels and advanced audit exports.

## Operational / Integration
- Managed deployment artifacts or config templates for private customers.
- Private adapters for proprietary telemetry sources.

## Notes
- Public code should only expose stable interfaces and schemas.
- Private code should be build‑tagged (`//go:build private`) or located in a separate private module.

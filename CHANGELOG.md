# Changelog

## 2026-02-07
### Added
- Ticketing workflow (tickets per thread) with UI list/detail and export.
- Thread formation confidence + reason fields in outputs and UI.
- Multi-entity synthetic thread suite (`data/synthetic_threads.json`).
- MITRE coverage reporting (`system coverage`) and documentation.
- Environment-scoped MITRE coverage (`system coverage -env`).
- Confidence band reporting (`system confidence -report`).
- Expanded realistic scenario suite + decision label/ticket status tests.
- Vendor fixture expansion to produce threads.
- Additional vendor auth fixtures for MDE and Sentinel.
- Updated vendor field mapping documentation for auth and trust-boundary events.
- Sample CLI outputs for MITRE coverage and reasoning (`docs/sample_outputs.md`).
- README docs section linking outputs and vendor mappings.
- Regression report output for `evaluate` (`docs/regression_report.md`).
- UI layout refresh with sidebar navigation, confidence meter, and attack-graph canvas.
- CI now publishes a regression report artifact and documents CI checklist.
- Release checklist documentation.
- File-based state ingestion (AWS/Okta/Azure/GCP) with schema docs and CLI `ingest-inventory`.
- Drift detection against existing env.json with `inventory-drift`.
- API adapter scaffolding for AWS/Okta/Azure/GCP (config schema + CLI).
- AWS live inventory adapter (IAM + EC2 + SGs + VPCs + subnets).
- Okta live inventory adapter (users, groups, roles, apps).
- Azure/Entra live inventory adapter (Graph users/groups/roles + ARM networks/NSGs).
- GCP live inventory adapter (projects, IAM bindings, service accounts, networks, firewalls).
- Inventory refresh + randomized scheduler with drift request output.
- Architecture diagram (`docs/architecture.md`).
- Embedded architecture diagram in README.
- Topology ingestion (routes/peerings) for AWS/Azure/GCP with trust-boundary derivation.
- Expanded vendor fixtures and mapping tests (Elastic ECS IAM/auth, Splunk auth, Okta admin role, Sentinel auth failure, CrowdStrike file events).
- Baseline validation report (`docs/BASELINE_REPORT.md`, `docs/BASELINE_REPORT.pdf`).

### Changed
- Decision labels and reason-code handling for feasible items.
- Thread clustering logic now avoids ambiguous global fallbacks.
- Rule catalog expansion with new techniques (log tampering, bulk exfil, admin protocol lateral).
- Vendor field normalization depth increased across adapters.
- Sentinel CSL normalization now maps authentication success/failure to normalized event types.

### Fixed
- Gated rule packs now surface as `admin_hold` placeholders.
- UI rendering and ticket export stability improvements.

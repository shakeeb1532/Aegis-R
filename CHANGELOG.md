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

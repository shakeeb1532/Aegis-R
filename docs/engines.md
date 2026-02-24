# Optional Engines (External Modules)

Aman can reference external engines as **separate modules**. These are not bundled inside the core repo and do not change reasoning verdicts by default. They are intended as **pluggable engines** that can be wired in when you are ready, without coupling them to the core.

## Current External Engines

1. **Blackbox Data Engine**
   - Purpose: Efficient storage/retrieval for large event, audit, and state payloads.
   - Repo: https://github.com/shakeeb1532/blackbox-data
   - Integration: planned adapter (storage backend or cache layer).

2. **Time Travel Forensics Engine**
   - Purpose: Replay and diff historical states for incident forensics and post-mortems.
   - Repo: https://github.com/shakeeb1532/TimeTravel-Forensics
   - Integration: planned adapter (audit replay + state rewind).

## How Aman Will Use Them (Planned)

- **Blackbox Data** as an optional storage engine for:
  - `audit.log`, `report.json`, SIEM exports.
  - Cold storage snapshots for `state.json`.
- **Time Travel Forensics** as an optional engine for:
  - Incident replay.
  - State diffs across time windows.

These engines remain **separate codebases** to protect IP and keep the Aman core minimal, stable, and auditable.

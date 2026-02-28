# Identity Case (Redacted)

This folder contains one end-to-end identity case to validate outputs.

**Correlation scope:** each normalized event includes `details.signInId` (e.g., `si-123`).

## Files
- `raw_signins.json` — redacted Graph-like sign-in events
- `normalized_events.json` — Aman evidence events derived from raw input
- `report.json` — assessment output
- `why_chain.json` — causal why-chain (extracted from bundle)
- `audit.log` — audit hash chain
- `evidence.zip` — evidence bundle
- `manifest.json` — bundle manifest (extracted from bundle)
- `commands.txt` — exact CLI commands used

## Notes
- Contradiction is demonstrated via `account_locked` (legacy contradiction for `TA0006.VALID_ACCOUNTS`).
- Correlation by `signInId` is present in data, but engine contradiction matching is currently rule-level (not correlation-aware).

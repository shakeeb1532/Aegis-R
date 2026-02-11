# UI API Contract (Demo)

Base URL (dev): `http://localhost:8081`

## Endpoints

### `GET /api/overview`
Returns KPI summary, headline verdict, evidence gaps, drift signals, and suggested actions.

### `GET /api/reasoning`
Returns detailed reasoning cards for the Reasoning screen.

### `GET /api/queue`
Returns analyst queue items derived from ticketed findings.

### `GET /api/governance`
Returns approvals (JSONL in `data/approvals.log`).

### `GET /api/audit`
Returns audit artifacts (JSONL in `data/audit.log`).

### `GET /api/evaluations`
Returns evaluation metrics.

### `GET /api/graph`
Returns thread summaries used by the Attack Graph page.

## Notes
- This API is intentionally minimal and file-backed for demos.
- Production SaaS should replace these endpoints with real data sources and auth.

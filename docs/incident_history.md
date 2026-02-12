# Incident History Schema (ML Assist)

This file provides optional history data for advisory ML‑assist features:
- telemetry recommendations
- feasible finding ranking (identity + cloud only)
- similar incident suggestions and playbooks

The ML assist never changes verdicts; it only adds advisory fields.

## File Format

JSON with a top‑level `incidents` array.

```json
{
  "incidents": [
    {
      "id": "inc-001",
      "rule_ids": ["TA0006.IDENTITY_ANOMALY", "TA0004.MFA_BYPASS"],
      "outcome": "confirmed",
      "missing_evidence": ["valid_account_login"],
      "summary": "Identity anomaly followed by MFA disable",
      "playbook": "idp-account-takeover"
    }
  ]
}
```

### Fields
- `id` (string): incident identifier
- `rule_id` (string, optional): single rule id
- `rule_ids` (array, optional): multiple rule ids
- `outcome` (string): e.g., `confirmed`, `false_positive`, `benign`
- `missing_evidence` (array): evidence types that were missing at the time
- `summary` (string): short incident summary
- `playbook` (string): playbook or response template id

## CLI Usage

```bash
go run ./cmd/aman reason event -in data/demo_events.json \
  --ml-assist \
  --ml-history data/incident_history.json
```

```bash
go run ./cmd/aman assess \
  -in data/demo_events.json \
  -env data/env.json \
  -state data/state.json \
  -audit data/audit.log \
  -baseline data/zero_trust_baseline.json \
  --ml-assist \
  --ml-history data/incident_history.json
```


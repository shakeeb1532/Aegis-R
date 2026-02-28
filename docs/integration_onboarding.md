# Integration Onboarding (Fast Path)

Use this flow to onboard EDR, cloud, and identity integrations with minimal setup.

## 1) Run Quickstart
```bash
go run ./cmd/aman system integration-quickstart \
  -rules data/rules.json \
  -outdir data/onboarding \
  -out docs/integration_quickstart.json
```

This generates per-category artifacts:
- `data/onboarding/identity_events.normalized.json`
- `data/onboarding/identity_report.ai_overlay.json`
- `data/onboarding/cloud_events.normalized.json`
- `data/onboarding/cloud_report.ai_overlay.json`
- `data/onboarding/edr_events.normalized.json`
- `data/onboarding/edr_report.ai_overlay.json`

## 2) Verify Integration Readiness
```bash
go run ./cmd/aman system integration-readiness \
  -rules data/rules.json \
  -out docs/integration_readiness.json
```

Strict gate mode:
```bash
go run ./cmd/aman system integration-readiness \
  --strict --min-events 1 --min-feasible 0 \
  -rules data/rules.json \
  -out docs/integration_readiness.json
```

## 3) Confirm Aman Escalation Authority
In generated reports, `ai_alerts[*].status` can be:
- `escalated`
- `triaged`
- `suppressed`

Aman is the escalation authority. AI candidates are automatically downgraded unless deterministic feasibility passes.

## 4) Generate ROI + Demo Pack
```bash
go run ./cmd/aman system roi-scorecard \
  -pilot docs/pilot_metrics_report.json \
  -integration docs/integration_readiness.json \
  -benchmark docs/production_benchmark_report.md \
  -out docs/roi_scorecard.md

go run ./cmd/aman system demo-pack \
  -outdir docs/demo_pack \
  -rules data/rules.json
```

---

## Identity Wedge (Entra Graph Sign-Ins)

### 1) Pull raw sign-ins (Graph)
```bash
aman ingest entra-pull \
  --tenant <TENANT_ID> \
  --client-id <APP_ID> \
  --client-secret <CLIENT_SECRET> \
  --start 2026-02-27T06:00:00Z \
  --end 2026-02-27T06:15:00Z \
  --out data/raw/entra/signins/raw_signins.json
```

Prefer env vars for secrets:
```
export ENTRA_TENANT_ID=...
export ENTRA_CLIENT_ID=...
export ENTRA_CLIENT_SECRET=...
```

### 2) Normalize into Aman atomic events
```bash
aman ingest entra-normalize \
  --in data/raw/entra/signins/raw_signins.json \
  --out data/normalized_events.json
```

### 3) Ingest normalized events
```bash
curl -X POST "http://localhost:8080/ingest?schema=native" \
  -H "Content-Type: application/json" \
  -d @data/normalized_events.json
```

Or ingest raw sign-ins directly (same normalization logic as `entra-normalize`):
```bash
curl -X POST "http://localhost:8080/ingest?schema=entra_signins_graph" \
  -H "Content-Type: application/json" \
  -d @data/raw/entra/signins/raw_signins.json
```

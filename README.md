# Aegis-R

License: Apache-2.0

Aegis-R is a **human-governed security reasoning infrastructure** that evaluates causal feasibility, maintains attack progression state, and produces audit-ready, tamper-evident explanations. It is designed to **reduce false positives** by eliminating impossible attack paths while preserving human authority and compliance.

## What It Does
- Determines whether a security event is **logically possible** in your environment.
- Proves why an alert is **real, impossible, or incomplete** (not just “high/low risk”).
- Maintains **live attack-progression state**, not isolated alerts.
- Explains every decision with a **clear reasoning chain** and evidence gaps.
- Produces **audit-ready artifacts** with hash chaining and signatures.
- Integrates alongside existing SIEM / EDR / XDR systems (no auto-remediation).

## What It Explicitly Does NOT Do
- Does **not** automatically block or remediate threats.
- Does **not** replace SIEM, EDR, or analysts.
- Does **not** rely on black-box AI decisions.
- Does **not** silently adapt trust based on attacker behavior.

## Core Concepts
- **Reasoning**: Event feasibility checks using environment and rule preconditions.
- **Progression**: A live attack-progression model that tracks attacker position, confidence, and reachability over time.
- **Audit**: Tamper-evident decision logs and signed artifacts.
- **Governance**: Human approvals and constraints that bind reasoning outcomes.
- **Zero-Trust Initialization**: A strict install-time scan that creates a baseline and prevents poisoning.

## Docs
- `docs/sample_outputs.md` — example MITRE coverage and reasoning outputs
- `docs/regression_report.md` — evaluate output with accuracy + mismatches
- `docs/vendor_mappings.md` — field-level normalization per vendor
- `docs/mitre_coverage.md` — rule catalog MITRE mapping notes
- `docs/confidence_bands.md` — confidence band interpretation
- `docs/ci_checklist.md` — CI checklist and local verification steps
- `docs/release_checklist.md` — release steps and tagging guidance
- `docs/inventory_schema.md` — file-based inventory ingestion schema

---

## Quick Start

### 1) Install Go
```bash
brew install go
```

### 2) Initialize Zero-Trust Baseline (Required)
```bash
go run ./cmd/aegisr init-scan \
  -baseline data/zero_trust_baseline.json \
  -out init_scan_report.json
```

### 3) Generate Synthetic Events
```bash
go run ./cmd/aegisr generate -out events.json -count 80
```

### 4) Run Reasoning (CLI)
```bash
go run ./cmd/aegisr reason -in events.json -rules data/rules.json -format cli
```

### 5) Run Full Assessment (JSON)
```bash
go run ./cmd/aegisr assess \
  -in events.json \
  -env data/env.json \
  -state state.json \
  -audit audit.log \
  -policy data/policy.json \
  -config data/ops.json \
  -baseline data/zero_trust_baseline.json \
  -format json
```

---

## One Command Local Demo

Run a full local demo (UI up + sample ingest + report generated):
```bash
make demo
```

Or run with Docker Compose:
```bash
docker compose up --build
```

---

## Zero-Trust Initialization (Poison Resistance)

Aegis-R requires a **strict initialization scan** on first install. The baseline is immutable unless an **admin** explicitly overrides.

### Run Init Scan
```bash
go run ./cmd/aegisr init-scan \
  -baseline data/zero_trust_baseline.json \
  -out init_scan_report.json
```

### Fast Baseline Check (Assess Only)
- `assess` only checks baseline integrity.
- If baseline is missing, `assess` **refuses to run** and instructs the installer to run `init-scan`.

### Override Policy
- Overrides require a **signed admin approval**.
- Aegis-R will display **explicit warnings** and a liability waiver if a baseline issue is overridden.

---

## CLI Commands

### Core
- `generate` — generate synthetic events
- `reason` — feasibility reasoning only
- `assess` — reasoning + progression + audit artifacts + integration hooks

### Governance
- `keys` — generate keypair
- `approve` — create approval (single)
- `approve2` — create dual approval
- `verify` — verify approval
- `profile-add` — add analyst reasoning profile
- `constraint-add` — add reasoning constraint
- `disagreement-add` — record analyst disagreement
- `govern ticket list|show|close` — ticket workflow over reasoning threads

### Audit
- `audit-verify` — verify hash chain
- `audit-sign` — sign audit artifacts

### Evaluation
- `generate-scenarios` — build synthetic labeled scenarios
- `evaluate` — evaluate accuracy on scenarios

### System
- `system status` — baseline + profile status
- `system health` — component health summary
- `system coverage` — MITRE coverage report (rules -> tactics/techniques)
- `system coverage -env data/env.json` — environment-scoped coverage
- `system confidence -report report.json` — confidence band report
- `system coverage -out docs/coverage_env.md` — save coverage as Markdown
- `system confidence -out docs/confidence_report.md` — save confidence bands as Markdown

### Integration
- `ingest-http` — HTTP ingest endpoint
- `ingest-inventory` — build `env.json` from inventory exports
- `inventory-drift` — compare inventory build to baseline env.json
- `ui` — lightweight analyst UI

### Zero-Trust
- `init-scan` — strict install-time baseline creation
- `scan` — compare current system to baseline

---

## Governance & Approval Flow

### Generate Keys
```bash
go run ./cmd/aegisr keys -out keypair.json
```

### Approve (Single)
```bash
go run ./cmd/aegisr approve \
  -key keypair.json \
  -id change-1 \
  -ttl 10m \
  -okta true \
  -signer alice \
  -role approver \
  -out approval.json
```

### Approve (Dual)
```bash
go run ./cmd/aegisr approve2 \
  -key1 keypair.json \
  -key2 keypair.json \
  -id change-1 \
  -ttl 10m \
  -okta true \
  -signer1 alice \
  -signer2 bob \
  -out dual_approval.json
```

---

## Integration Schemas

Supported `schema` values for ingestion:
- `ecs`
- `elastic_ecs`
- `ocsf`
- `cim`
- `splunk_cim_auth`
- `splunk_cim_net`
- `mde` (`kind=device|identity`)
- `okta_systemlog`
- `aws_cloudtrail`
- `sentinel_csl`
- `crowdstrike_fdr`

Example:
```bash
curl -X POST "http://localhost:8080/ingest?schema=ecs" -d @data/fixtures/ecs/sample.json
```

---

## State Ingestion (Inventory + Topology + IAM)

Build the environment model directly from file-based inventory exports:

```bash
go run ./cmd/aegisr ingest-inventory -in data/inventory -out data/env.json
```

See `docs/inventory_schema.md` for the JSON schema per provider.

Adapter scaffolding (API-ready, requires credentials):

```bash
go run ./cmd/aegisr inventory-adapter -provider aws -config data/inventory/config.json -out data/env.json
```

AWS, Okta, Azure, and GCP adapters support live ingestion using standard credentials (AWS chain, Okta token, Azure client credentials, GCP ADC or service account).

Vendor field normalization details are in:
- `docs/vendor_mappings.md`

---

## Normalized Envelope (Internal Model)

Aegis-R adapters normalize events into a stable envelope:
- `timestamp`
- `source` (EDR/IdP/CloudTrail/etc.)
- `principal` (identity)
- `asset` (host/resource)
- `action` (normalized verb)
- `evidence` (raw refs)
- `confidence` (scoring)
- `tags` (zone, criticality)

Confidence is **heuristic and rule-based**, not calibrated ML. Outputs and UI explicitly label the confidence model.

Decision labels: `suppress` / `deprioritize` / `keep` / `escalate` are layered on top of feasibility verdicts.
Local decision cache scope: host + principal + rule with a 24h TTL.
Threads are clustered by host + principal within a 2h window.
Thread formation includes a confidence score and reason for why clustering did or didn’t occur.

Synthetic thread suite:
- `data/synthetic_threads.json` (multi-entity events that yield 2–3 threads)

Baseline validation report:
- `docs/BASELINE_REPORT.md`
- `docs/BASELINE_REPORT.pdf`

---

## Attack Progression Model

Aegis-R maintains a live **attack progression graph** with:
- Graph-based current attacker position overlay
- Confidence decay over time
- Time-windowed progression (default last 24h)

Minimal trigger set covers most real intrusions:
- Identity and Auth events
- Privilege escalation and role changes
- Suspicious host execution and credential access
- Lateral movement and inbound admin protocols
- Exfil and impact indicators

---

## Analyst UI (Lightweight)

Start UI:
```bash
go run ./cmd/aegisr ui \
  -addr :9090 \
  -audit audit.log \
  -signed-audit signed_audit.log \
  -approvals approvals.log \
  -report report.json \
  -profiles analyst_profiles.json \
  -disagreements disagreements.log \
  -key keypair.json \
  -basic-user admin \
  -basic-pass pass
```

Features:
- Audit timeline
- Approval history with rationale and evidence gaps
- Role-gated approvals (analyst, approver, admin)
- Signed artifact verification (valid/invalid)
- Per-rule evidence drilldown
- Search/filter for audit + approvals
- Export buttons for audit + signed artifacts
- Tickets list + detail view
- Ticket export (JSON) for compliance

---

## Evaluation Harness

Generate scenarios:
```bash
go run ./cmd/aegisr generate-scenarios -out data/scenarios.json -rules data/rules.json
```

Evaluate:
```bash
go run ./cmd/aegisr evaluate -scenarios data/scenarios.json -rules data/rules.json -format cli
```

Realistic scenarios:
```bash
go run ./cmd/aegisr evaluate -scenarios data/scenarios_realistic.json -rules data/rules.json -format cli
```

---

## Benchmarks

Reasoning:
```bash
go test ./internal/logic -bench BenchmarkReason -benchmem
```

Assessment:
```bash
go test ./internal/core -bench BenchmarkAssess -benchmem
```

---

## Audit Artifacts

- `audit.log` is **hash chained**
- `audit-sign` produces **signed audit logs**

```bash
go run ./cmd/aegisr audit-sign -audit audit.log -out signed_audit.log -signer soc-admin
```

---

## Configuration

`data/ops.json` controls logging, metrics, and strictness:
```json
{
  "log_level": "info",
  "metrics_on": true,
  "strict_mode": false
}
```

- `strict_mode=false` reduces memory by omitting full supporting event objects.

---

## Kubernetes Deployment (Helm)

### Requirements
1. Kubernetes 1.27+
2. Ingress controller (nginx default, ALB optional)
3. cert-manager for TLS (or provide a secret)

### Install
```bash
kubectl create namespace aegis-r
helm install aegis-r ./charts/aegis-r --namespace aegis-r
```

### Configure UI Basic Auth
```bash
kubectl -n aegis-r create secret generic aegisr-ui-basic --from-literal=password='change-me'
```

### Configure Signing Keys
```bash
kubectl -n aegis-r create secret generic aegisr-signing-keys --from-file=keypair.json
```

### Example Values Overrides
```bash
helm upgrade --install aegis-r ./charts/aegis-r \
  --namespace aegis-r \
  --set ingress.host=aegisr.example.com \
  --set ingress.tls.secretName=aegisr-tls \
  --set ui.basicPassSecretCreate=false \
  --set signingKeySecret.create=false \
  --set signingKeySecret.name=aegisr-signing-keys
```

---

## Docker

```bash
docker build -t aegisr .
docker run -p 8080:8080 aegisr
```

---

## Release Artifacts

- Container images: `ghcr.io/shakeeb1532/aegis-r:<tag>` and `latest`
- Versioned binaries via GoReleaser (tagged releases)

---

## Repository Structure
- `cmd/aegisr/` — CLI entrypoint
- `internal/logic/` — reasoning engine
- `internal/core/` — stateful assessment
- `internal/progression/` — attack progression model
- `internal/audit/` — audit chain + signing
- `internal/governance/` — policy + roles
- `internal/integration/` — adapters + ingest
- `internal/ui/` — analyst UI
- `internal/eval/` — evaluation harness
- `data/` — sample rules/env/scenarios/fixtures
- `docs/` — vendor mapping documentation
- `docs/mitre_coverage.md` — MITRE coverage reporting usage

---

## Roadmap (Suggested)
- Production auth (OIDC / SSO integration)
- Vendor-specific adapter expansion (more fields, more products)
- Rule catalog growth (full MITRE coverage)
- Hardened production packaging (Helm refinement, systemd)

---

## License
TBD

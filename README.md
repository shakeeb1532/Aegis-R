# Aegis-R

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

---

## Quick Start

### 1) Generate Synthetic Events
```bash
go run ./cmd/aegisr generate -out events.json -count 80
```

### 2) Run Reasoning (CLI)
```bash
go run ./cmd/aegisr reason -in events.json -rules data/rules.json -format cli
```

### 3) Run Full Assessment (JSON)
```bash
go run ./cmd/aegisr assess \
  -in events.json \
  -env data/env.json \
  -state state.json \
  -audit audit.log \
  -policy data/policy.json \
  -config data/ops.json \
  -format json
```

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

### Audit
- `audit-verify` — verify hash chain
- `audit-sign` — sign audit artifacts

### Evaluation
- `generate-scenarios` — build synthetic labeled scenarios
- `evaluate` — evaluate accuracy on scenarios

### Integration
- `ingest-http` — HTTP ingest endpoint
- `ui` — lightweight analyst UI

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

Vendor field normalization details are in:
- `docs/vendor_mappings.md`

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
  -key keypair.json \
  -basic-user admin \
  -basic-pass pass
```

Features:
- Audit timeline
- Approval history
- Download audit logs
- Signed artifact verification (valid/invalid)
- Per-rule evidence drilldown
- Role-gated approvals (approver/admin)

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

## Docker

```bash
docker build -t aegisr .
docker run -p 8080:8080 aegisr
```

---

## Repository Structure

- `cmd/aegisr/` — CLI entrypoint
- `internal/logic/` — reasoning engine
- `internal/core/` — stateful assessment
- `internal/audit/` — audit chain + signing
- `internal/governance/` — policy + roles
- `internal/integration/` — adapters + ingest
- `internal/ui/` — analyst UI
- `internal/eval/` — evaluation harness
- `data/` — sample rules/env/scenarios/fixtures
- `docs/` — vendor mapping documentation

---

## Roadmap (Suggested)
- Production auth (OIDC / SSO integration)
- Vendor-specific adapter expansion (more fields, more products)
- Rule catalog growth (full MITRE coverage)
- Deployment packaging (Helm / systemd)

---

## License
TBD

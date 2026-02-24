# Aman Technical White Paper

Version: 1.0  
Date: 2026-02-23  
Project: Aman (formerly Aegis-R)

## Abstract

Aman is a human-governed security reasoning engine designed to reduce false positives by testing whether attack paths are *causally feasible* in a specific environment. Unlike alert-ranking tools that primarily score anomalies, Aman evaluates preconditions, trust-boundary reachability, identity privilege requirements, and observed evidence consistency. The output is an auditable, tamper-evident decision trail suitable for SOC operations, incident response, and compliance workflows.

## Problem Statement

Modern SOC teams receive high alert volumes from SIEM/EDR/XDR systems. Most alerts are incomplete, context-poor, or non-actionable. This causes:

- Alert fatigue and analyst burnout
- Slow triage for true incidents
- Inconsistent decisions across shifts
- Weak audit defensibility for incident actions

Aman addresses this by shifting from “alert severity” to “feasibility with proof.”

## Design Goals

- Determine whether an attack claim is possible, incomplete, conflicted, or policy-impossible
- Preserve human control over high-impact trust decisions
- Produce explainable outputs with explicit reason codes
- Integrate with existing security telemetry sources
- Maintain tamper-evident governance and audit artifacts

## System Architecture

### Core Components

- Ingestion and normalization layer (`internal/integration`)
- Causal reasoning engine (`internal/logic`, `internal/causal`)
- Progression and thread state (`internal/progression`, `internal/state`)
- Governance and approvals (`internal/approval`, `internal/governance`)
- Tamper-evident audit chain (`internal/audit`)
- CLI control plane (`cmd/aman`)

### Data Flow

1. Events are ingested from supported schemas (ECS/OCSF/CIM/vendor-specific adapters).
2. Events are normalized into Aman internal event envelopes.
3. Rules and environment state are evaluated causally.
4. Progression graph and decision labels are updated.
5. Signed governance/audit outputs are emitted for verification/export.

## Causal Feasibility Engine

### Model

Aman uses structural causal modeling (SCM) to evaluate rule feasibility:

- Requirements become causal input variables (`req:*`)
- Preconditions become causal input variables (`pre:*`)
- Environment gates become causal inputs (`gate:*`)
- Outcome is `outcome:feasible = AND(req, pre, gate)`

This enables:

- Explicit blockers (`CausalBlockers`)
- Necessary single causes (`NecessaryCauses`)
- Minimal joint cause sets (`NecessaryCauseSets`)

### Safety Controls

- Joint-cause search depth capped (safe bound) to control combinatorial growth
- Causal model validation for undeclared variables and cycles
- Error propagation to reasoning results (`CausalError`) instead of silent failure

## Environment-Aware Reasoning

### Reachability

Aman builds a trust-boundary graph and evaluates lateral feasibility against reachable zones.

- Directional allow edges are modeled
- Deny boundaries are enforced in traversal
- Reverse reachability is available for blast-radius style queries

### Identity Privilege Gating

Rules requiring elevated privilege are blocked when actor privilege is insufficient or unknown (fail-safe behavior). This prevents optimistic false feasibility.

## Decision Semantics

Aman supports distinct outcome semantics:

- `feasible`: evidence + preconditions + gates satisfied
- `incomplete`: partial support, missing required evidence/context
- `conflicted`: contradictory evidence invalidates required condition
- `policy_impossible`: governance-declared impossible path, enforced by policy

Each result includes reason codes to keep triage deterministic and machine-actionable.

## Governance, Signing, and Audit Integrity

### Approvals

- Signed approvals with TTL and optional Okta verification
- Dual-approval enforcement (`min_signers >= 2`)
- Role-gated signer checks

### Audit Chain

- Hash-chained artifacts (`PrevHash -> Hash`) for tamper evidence
- Chain verification detects mutation/reordering
- Signed artifact verification bound to trusted signer registry

## Integration Layer

### Supported Input Families

- Native Aman JSON events
- ECS / Elastic ECS
- OCSF
- CIM / Splunk CIM
- CloudTrail
- Okta
- Sentinel
- CrowdStrike
- MDE

### Ingest Security Controls

- Optional API key authentication (`AMAN_INGEST_API_KEY`)
- Request body size limits for HTTP ingest
- Structured JSON error responses for integration diagnostics

## Performance and Operability

### Operational Characteristics

- Deterministic reasoning outputs for identical inputs and config
- Memory-conscious state persistence and compressed log/export support
- CLI-first workflow for automation and repeatability

### Observability

- Rule/event metrics support via ops instrumentation
- Health endpoints for integration checks
- Explicit failure surfacing in reason and audit paths

## Security Posture

### Current Strengths

- Causal gating reduces unsupported escalation
- Signed governance and audit artifacts
- Path validation and safer file handling patterns
- Ingest endpoint hardening controls

### Residual Risk Areas

- Coverage quality remains dependent on normalization fidelity and rule catalog depth
- Confidence scores are heuristic and should be calibrated per deployment
- Long-horizon audit verification still benefits from incremental verify/index enhancements

## Validation Status

Recent validation includes:

- Unit and integration test suite across logic/env/audit/approval/integration/core
- Race testing on critical concurrency-heavy packages
- Benchmark and metrics artifacts in `docs/benchmarks` and related reports

For execution details and snapshots, see:

- `docs/production_benchmark_report.md`
- `docs/pilot_metrics_report.md`
- `docs/metrics_report.md`

## Deployment Model

Aman supports:

- Local/CLI deployments
- Containerized deployments
- Hosted SaaS pilot patterns (single-node then scaled)

Recommended production guardrails:

- Dedicated trusted signer registry management
- Key rotation policy and signer lifecycle controls
- Environment inventory refresh and drift review workflow

## Limitations

- Not an auto-remediation platform by design
- Does not replace SIEM/EDR/XDR data sources
- Model quality depends on telemetry completeness and schema mapping quality
- Requires governance setup for strongest compliance posture

## Roadmap (Technical)

- Expand MITRE/NIST/Kill Chain mapping depth with explicit coverage scoring
- Improve adapter precision for vendor field-level normalization
- Add incremental audit verification/indexing for very large logs
- Extend calibration tooling for confidence tuning in pilot environments

## Conclusion

Aman is positioned as a causal reasoning and governance layer for existing SOC stacks. Its primary value is not alert volume handling, but defensible feasibility determination with explicit human control and audit-grade evidence chains.


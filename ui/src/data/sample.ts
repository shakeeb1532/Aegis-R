import { Approval, AuditItem, Evaluation, QueueItem, ReasoningItem } from "../types";

export const overviewKpis = [
  { label: "Active Threads", value: "4", sub: "Last 24h" },
  { label: "Feasible Findings", value: "9", sub: "3 require review" },
  { label: "Evidence Gaps", value: "7", sub: "2 critical" },
  { label: "Governance Holds", value: "2", sub: "Awaiting dual sign" }
];

export const reasoningSamples: ReasoningItem[] = [
  {
    id: "R-1841",
    title: "Impossible Travel + New Device Login",
    verdict: "POSSIBLE",
    confidence: 0.78,
    summary: "Credentials likely reused across devices with no verified MFA event.",
    evidence: ["Okta new_device_login", "Geo distance 6,210km", "Known session reuse"],
    gaps: ["No MFA challenge recorded", "No device posture assertion"],
    nextMoves: ["Verify MFA logs", "Inspect device posture for user"],
    updated: "2m ago"
  },
  {
    id: "R-1842",
    title: "Admin Role Change + OAuth Consent",
    verdict: "CONFIRMED",
    confidence: 0.91,
    summary: "Privilege escalation is feasible with confirmed admin role change.",
    evidence: ["Entra admin_role_add", "Consent grant to unknown app"],
    gaps: ["Missing justification ticket"],
    nextMoves: ["Revoke consent", "Validate admin requester"],
    updated: "11m ago"
  }
];

export const queueItems: QueueItem[] = [
  {
    id: "Q-9001",
    rule: "MFA disabled",
    verdict: "INCOMPLETE",
    confidence: 0.54,
    evidence: ["MFA policy change", "User flagged high risk"],
    gaps: ["No MFA reset ticket", "No device attestation"],
    principal: "s.vasquez@corp",
    asset: "IdP",
    updated: "6m ago"
  },
  {
    id: "Q-9002",
    rule: "Token refresh anomaly",
    verdict: "POSSIBLE",
    confidence: 0.71,
    evidence: ["Refresh token used from new ASN", "Session overlap"],
    gaps: ["Missing endpoint telemetry"],
    principal: "svc-build@corp",
    asset: "M365",
    updated: "14m ago"
  },
  {
    id: "Q-9003",
    rule: "LOLBIN execution",
    verdict: "IMPOSSIBLE",
    confidence: 0.62,
    evidence: ["Encoded PowerShell observed"],
    gaps: ["No host reachability from attacker thread"],
    principal: "d.rana@corp",
    asset: "laptop-33",
    updated: "25m ago"
  }
];

export const approvals: Approval[] = [
  {
    id: "A-4011",
    scope: "Promote svc-backup to CONFIRMED",
    status: "DUAL",
    approver: "a.norton",
    expires: "in 45m"
  },
  {
    id: "A-4012",
    scope: "Override evidence gap: no ticket",
    status: "PENDING",
    approver: "m.lee",
    expires: "in 2h"
  }
];

export const auditItems: AuditItem[] = [
  {
    id: "artifact-1770360655",
    timestamp: "2026-02-11 09:42 UTC",
    summary: "Causal feasibility, progression state, and evidence gaps evaluated.",
    signer: "aegisr"
  },
  {
    id: "artifact-1770360149",
    timestamp: "2026-02-11 09:12 UTC",
    summary: "Governance decision signed and verified.",
    signer: "a.norton"
  }
];

export const evaluations: Evaluation[] = [
  {
    label: "Synthetic accuracy",
    value: "0.887",
    delta: "+0.012",
    note: "106 labeled scenarios"
  },
  {
    label: "Public dataset consistency",
    value: "0.903",
    delta: "+0.008",
    note: "31 labeled events"
  },
  {
    label: "Pilot impact (est.)",
    value: "-42% triage",
    delta: "est.",
    note: "based on feasible vs impossible splits"
  }
];

export const evidenceGaps = [
  "No MFA challenge for risky sign-in",
  "Missing device posture assertion",
  "No change ticket for admin role",
  "Endpoint telemetry missing for token refresh"
];

export const driftSignals = [
  "New admin role created without approval",
  "OAuth consent to unknown app",
  "New device joined to tenant"
];

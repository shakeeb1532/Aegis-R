import { Approval, AuditItem, Evaluation, GraphResponse, QueueItem, ReasoningItem } from "../types";

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
    reason_code: "high_risk_identity_signal",
    confidence: 0.78,
    confidence_factors: {
      coverage: 0.66,
      recency: 0.9,
      corroboration: 0.4,
      evidence_present: 2,
      evidence_total: 3,
      supporting_events: 4,
      missing_evidence: 1,
      coverage_weight: 0.65,
      recency_weight: 0.2,
      corroboration_weight: 0.1,
      raw_score: 0.79,
      floor: 0.1,
      ceiling: 0.95
    },
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
    reason_code: "privilege_escalation",
    confidence: 0.91,
    confidence_factors: {
      coverage: 1.0,
      recency: 0.8,
      corroboration: 0.6,
      evidence_present: 3,
      evidence_total: 3,
      supporting_events: 6,
      missing_evidence: 0,
      coverage_weight: 0.65,
      recency_weight: 0.2,
      corroboration_weight: 0.1,
      raw_score: 0.88,
      floor: 0.1,
      ceiling: 0.95
    },
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
    status: "dual_approved",
    approver: "a.norton",
    expires: "in 45m",
    template_id: "high_risk"
  },
  {
    id: "A-4012",
    scope: "Override evidence gap: no ticket",
    status: "pending_second_approval",
    approver: "m.lee",
    expires: "in 2h",
    template_id: "safe_change"
  }
];

export const auditItems: AuditItem[] = [
  {
    id: "artifact-1770360655",
    timestamp: "2026-02-11 09:42 UTC",
    summary: "Causal feasibility, progression state, and evidence gaps evaluated.",
    signer: "aman"
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

export const tuningSamples = [
  {
    rule_id: "TA0006.SIGNIN_SUCCESS",
    enabled: true,
    min_confidence: 0.6,
    require_approval: true
  }
];

export const graphSample: GraphResponse = {
  threads: [
    {
      id: "thread-1",
      host: "host-1",
      principal: "alice@example.com",
      rule_ids: ["TA0006.SIGNIN_SUCCESS", "TA0006.RISK_LEVEL_HIGH_SUCCESS"],
      confidence: 0.72,
      reason: "High-risk sign-in success"
    }
  ],
  nodes: [
    { id: "host:host-1", label: "host-1", kind: "host", status: "compromised" },
    { id: "host:host-2", label: "host-2", kind: "host", status: "reachable" },
    { id: "identity:alice@example.com", label: "alice@example.com", kind: "identity", status: "compromised" },
    { id: "identity:svc-backup", label: "svc-backup", kind: "identity", status: "reachable" }
  ],
  edges: [
    { from: "host:host-1", to: "host:host-2", label: "reachable", status: "incomplete" },
    { from: "identity:alice@example.com", to: "identity:svc-backup", label: "reachable", status: "incomplete" }
  ],
  progression: [
    {
      time: "2026-02-27 10:04 UTC",
      stage: "identity_auth",
      action: "signin_success",
      principal: "alice@example.com",
      asset: "IdP",
      confidence: 0.78,
      rationale: "Successful sign-in with elevated risk"
    },
    {
      time: "2026-02-27 10:07 UTC",
      stage: "privilege_change",
      action: "admin_group_change",
      principal: "alice@example.com",
      asset: "Azure AD",
      confidence: 0.64,
      rationale: "Admin role added"
    }
  ]
};

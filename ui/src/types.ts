export type Verdict = "CONFIRMED" | "POSSIBLE" | "INCOMPLETE" | "IMPOSSIBLE";

export type HeaderStatus = {
  session_id: string;
  integrity: "verified" | "unknown" | "broken";
  integrity_note?: string;
  started_at?: string;
};

export type ReasoningItem = {
  id: string;
  title: string;
  verdict: Verdict;
  reason_code?: string;
  confidence: number;
  confidence_factors?: {
    coverage: number;
    recency: number;
    corroboration: number;
    evidence_present: number;
    evidence_total: number;
    supporting_events: number;
    missing_evidence: number;
    coverage_weight: number;
    recency_weight: number;
    corroboration_weight: number;
    raw_score: number;
    floor: number;
    ceiling: number;
  };
  summary: string;
  evidence: string[];
  gaps: string[];
  nextMoves?: string[];
  next_moves?: string[];
  updated: string;
};

export type FeedbackPayload = {
  decision_id: string;
  decision_title?: string;
  verdict: string;
  reason_code?: string;
  analyst_label: "agree" | "disagree" | "need_more_context";
  comment?: string;
};

export type RuleTuning = {
  rule_id: string;
  enabled: boolean;
  min_confidence: number;
  require_approval: boolean;
};

export type QueueItem = {
  id: string;
  rule: string;
  verdict: Verdict;
  confidence: number;
  evidence: string[];
  gaps: string[];
  principal: string;
  asset: string;
  updated: string;
};

export type Approval = {
  id: string;
  scope: string;
  status: string;
  approver: string;
  approvers?: string[];
  expires: string;
  dual_required?: number;
  valid_signers?: number;
  dual_approved?: boolean;
  okta_verified?: boolean;
  human_decision?: string;
  template_id?: string;
};

export type AuditItem = {
  id: string;
  timestamp: string;
  summary: string;
  signer: string;
};

export type Evaluation = {
  label: string;
  value: string;
  delta: string;
  note: string;
};

export type GraphNode = {
  id: string;
  label: string;
  kind: "host" | "identity";
  status: "compromised" | "reachable" | "observed";
};

export type GraphEdge = {
  from: string;
  to: string;
  label: string;
  status: "blocked" | "incomplete" | "feasible";
};

export type ProgressionItem = {
  time: string;
  stage: string;
  action: string;
  principal: string;
  asset: string;
  confidence: number;
  rationale: string;
};

export type GraphResponse = {
  threads: {
    id: string;
    host: string;
    principal: string;
    rule_ids: string[];
    confidence: number;
    reason: string;
  }[];
  nodes: GraphNode[];
  edges: GraphEdge[];
  progression: ProgressionItem[];
};

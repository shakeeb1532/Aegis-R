export type Verdict = "CONFIRMED" | "POSSIBLE" | "INCOMPLETE" | "IMPOSSIBLE";

export type ReasoningItem = {
  id: string;
  title: string;
  verdict: Verdict;
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
  nextMoves: string[];
  updated: string;
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
  status: "PENDING" | "DUAL" | "SIGNED";
  approver: string;
  expires: string;
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

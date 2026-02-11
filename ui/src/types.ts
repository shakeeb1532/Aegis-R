export type Verdict = "CONFIRMED" | "POSSIBLE" | "INCOMPLETE" | "IMPOSSIBLE";

export type ReasoningItem = {
  id: string;
  title: string;
  verdict: Verdict;
  confidence: number;
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

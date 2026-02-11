import { Approval, AuditItem, Evaluation, QueueItem, ReasoningItem } from "../types";

export type OverviewResponse = {
  kpis: { label: string; value: string; sub: string }[];
  headline: ReasoningItem;
  evidence_gaps: string[];
  drift_signals: string[];
  suggested_actions: string[];
};

export type ReasoningResponse = ReasoningItem[];
export type QueueResponse = QueueItem[];
export type GovernanceResponse = Approval[];
export type AuditResponse = AuditItem[];
export type EvaluationsResponse = Evaluation[];

export type GraphThread = {
  id: string;
  host: string;
  principal: string;
  rule_ids: string[];
  confidence: number;
  reason: string;
};

export type GraphResponse = {
  threads: GraphThread[];
};

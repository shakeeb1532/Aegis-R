import { useEffect, useState } from "react";
import { fetchJson } from "../api/client";
import {
  AuditResponse,
  EvaluationsResponse,
  GovernanceResponse,
  OverviewResponse,
  QueueResponse,
  ReasoningResponse
} from "../api/types";
import {
  approvals,
  auditItems,
  evaluations,
  evidenceGaps,
  driftSignals,
  overviewKpis,
  queueItems,
  reasoningSamples
} from "../data/sample";

const overviewFallback: OverviewResponse = {
  kpis: overviewKpis,
  headline: reasoningSamples[0],
  evidence_gaps: evidenceGaps,
  drift_signals: driftSignals,
  suggested_actions: [
    "Collect evidence: MFA challenge logs",
    "Validate device posture for new sign-ins"
  ]
};

export function useOverview() {
  const [data, setData] = useState<OverviewResponse>(overviewFallback);
  useEffect(() => {
    void fetchJson<OverviewResponse>("/api/overview", overviewFallback).then(setData);
  }, []);
  return data;
}

export function useReasoning() {
  const [data, setData] = useState<ReasoningResponse>(reasoningSamples);
  useEffect(() => {
    void fetchJson<ReasoningResponse>("/api/reasoning", reasoningSamples).then(setData);
  }, []);
  return data;
}

export function useQueue() {
  const [data, setData] = useState<QueueResponse>(queueItems);
  useEffect(() => {
    void fetchJson<QueueResponse>("/api/queue", queueItems).then(setData);
  }, []);
  return data;
}

export function useGovernance() {
  const [data, setData] = useState<GovernanceResponse>(approvals);
  useEffect(() => {
    void fetchJson<GovernanceResponse>("/api/governance", approvals).then(setData);
  }, []);
  return data;
}

export function useAudit() {
  const [data, setData] = useState<AuditResponse>(auditItems);
  useEffect(() => {
    void fetchJson<AuditResponse>("/api/audit", auditItems).then(setData);
  }, []);
  return data;
}

export function useEvaluations() {
  const [data, setData] = useState<EvaluationsResponse>(evaluations);
  useEffect(() => {
    void fetchJson<EvaluationsResponse>("/api/evaluations", evaluations).then(setData);
  }, []);
  return data;
}

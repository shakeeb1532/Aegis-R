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
  graphSample,
  driftSignals,
  overviewKpis,
  queueItems,
  reasoningSamples,
  tuningSamples
} from "../data/sample";
import { fetchTuning } from "../api/tuning";
import { RuleTuning } from "../types";

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
    void fetchJson<OverviewResponse>("/v1/overview", overviewFallback).then(setData);
  }, []);
  return data;
}

export function useReasoning() {
  const [data, setData] = useState<ReasoningResponse>(reasoningSamples);
  useEffect(() => {
    void fetchJson<ReasoningResponse>("/v1/reasoning", reasoningSamples).then(setData);
  }, []);
  return data;
}

export function useQueue() {
  const [data, setData] = useState<QueueResponse>(queueItems);
  useEffect(() => {
    void fetchJson<QueueResponse>("/v1/queue", queueItems).then(setData);
  }, []);
  return data;
}

export function useGovernance() {
  const [data, setData] = useState<GovernanceResponse>(approvals);
  useEffect(() => {
    void fetchJson<GovernanceResponse>("/v1/governance", approvals).then(setData);
  }, []);
  return data;
}

export function useAudit() {
  const [data, setData] = useState<AuditResponse>(auditItems);
  useEffect(() => {
    void fetchJson<AuditResponse>("/v1/audit", auditItems).then(setData);
  }, []);
  return data;
}

export function useEvaluations() {
  const [data, setData] = useState<EvaluationsResponse>(evaluations);
  useEffect(() => {
    void fetchJson<EvaluationsResponse>("/v1/evaluations", evaluations).then(setData);
  }, []);
  return data;
}

export function useGraph() {
  const [data, setData] = useState(graphSample);
  useEffect(() => {
    void fetchJson("/v1/graph", graphSample).then(setData);
  }, []);
  return data;
}

export function useTuning() {
  const [data, setData] = useState<RuleTuning[]>(tuningSamples);
  useEffect(() => {
    void fetchTuning().then(setData);
  }, []);
  return data;
}

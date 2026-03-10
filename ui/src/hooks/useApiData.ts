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
  headerSample,
  driftSignals,
  overviewKpis,
  queueItems,
  reasoningSamples,
  tuningSamples
} from "../data/sample";
import { fetchTuning } from "../api/tuning";
import { RuleTuning } from "../types";
import { HeaderResponse } from "../api/types";

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

type HookState<T> = { data: T; loading: boolean };

function useApiState<T>(path: string, fallback: T): HookState<T> {
  const [data, setData] = useState<T>(fallback);
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    let active = true;
    setLoading(true);
    void fetchJson<T>(path, fallback).then((next) => {
      if (!active) return;
      setData(next);
      setLoading(false);
    });
    return () => {
      active = false;
    };
  }, [path]);
  return { data, loading };
}

export function useOverview() {
  return useApiState<OverviewResponse>("/v1/overview", overviewFallback);
}

export function useHeader() {
  return useApiState<HeaderResponse>("/v1/header", headerSample);
}

export function useReasoning() {
  return useApiState<ReasoningResponse>("/v1/reasoning", reasoningSamples);
}

export function useQueue() {
  return useApiState<QueueResponse>("/v1/queue", queueItems);
}

export function useGovernance() {
  return useApiState<GovernanceResponse>("/v1/governance", approvals);
}

export function useAudit() {
  return useApiState<AuditResponse>("/v1/audit", auditItems);
}

export function useEvaluations() {
  return useApiState<EvaluationsResponse>("/v1/evaluations", evaluations);
}

export function useGraph() {
  return useApiState("/v1/graph", graphSample);
}

export function useTuning() {
  const [data, setData] = useState<RuleTuning[]>(tuningSamples);
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    let active = true;
    setLoading(true);
    void fetchTuning().then((next) => {
      if (!active) return;
      setData(next);
      setLoading(false);
    });
    return () => {
      active = false;
    };
  }, []);
  return { data, loading };
}

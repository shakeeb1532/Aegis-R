import { RuleTuning } from "../types";
import { apiKeyHeader, getApiKey } from "./auth";

const base = import.meta.env.VITE_API_BASE || "http://localhost:8081";

export async function fetchTuning(): Promise<RuleTuning[]> {
  const res = await fetch(`${base}/v1/tuning`, {
    headers: apiKeyHeader(getApiKey())
  });
  if (!res.ok) {
    return [];
  }
  const raw = (await res.json()) as any;
  return (raw?.data ?? raw) as RuleTuning[];
}

export async function postTuning(payload: RuleTuning) {
  const res = await fetch(`${base}/v1/tuning`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...apiKeyHeader(getApiKey())
    },
    body: JSON.stringify(payload)
  });
  if (!res.ok) {
    throw new Error("tuning_failed");
  }
  return res.json();
}

export async function fetchTuningHistory() {
  const res = await fetch(`${base}/v1/tuning/history`, {
    headers: apiKeyHeader(getApiKey())
  });
  if (!res.ok) {
    return [];
  }
  const raw = (await res.json()) as any;
  return (raw?.data ?? raw) as { id: string; at: string; note?: string }[];
}

export async function postTuningReset() {
  const res = await fetch(`${base}/v1/tuning/reset`, {
    method: "POST",
    headers: apiKeyHeader(getApiKey())
  });
  if (!res.ok) {
    throw new Error("tuning_reset_failed");
  }
  return res.json();
}

export async function postTuningRollback(snapshot_id: string) {
  const res = await fetch(`${base}/v1/tuning/rollback`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...apiKeyHeader(getApiKey())
    },
    body: JSON.stringify({ snapshot_id })
  });
  if (!res.ok) {
    throw new Error("tuning_rollback_failed");
  }
  return res.json();
}

import { RuleTuning } from "../types";

const base = import.meta.env.VITE_API_BASE || "http://localhost:8081";

function apiKey() {
  return (
    import.meta.env.VITE_API_KEY ||
    window.localStorage.getItem("amanApiKey") ||
    window.localStorage.getItem("ingestApiKey") ||
    ""
  );
}

export async function fetchTuning(): Promise<RuleTuning[]> {
  const key = apiKey();
  const res = await fetch(`${base}/v1/tuning`, {
    headers: key ? { "X-API-Key": key } : undefined
  });
  if (!res.ok) {
    return [];
  }
  const raw = (await res.json()) as any;
  return (raw?.data ?? raw) as RuleTuning[];
}

export async function postTuning(payload: RuleTuning) {
  const key = apiKey();
  const res = await fetch(`${base}/v1/tuning`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(key ? { "X-API-Key": key } : {})
    },
    body: JSON.stringify(payload)
  });
  if (!res.ok) {
    throw new Error("tuning_failed");
  }
  return res.json();
}

export async function fetchTuningHistory() {
  const key = apiKey();
  const res = await fetch(`${base}/v1/tuning/history`, {
    headers: key ? { "X-API-Key": key } : undefined
  });
  if (!res.ok) {
    return [];
  }
  const raw = (await res.json()) as any;
  return (raw?.data ?? raw) as { id: string; at: string; note?: string }[];
}

export async function postTuningReset() {
  const key = apiKey();
  const res = await fetch(`${base}/v1/tuning/reset`, {
    method: "POST",
    headers: key ? { "X-API-Key": key } : undefined
  });
  if (!res.ok) {
    throw new Error("tuning_reset_failed");
  }
  return res.json();
}

export async function postTuningRollback(snapshot_id: string) {
  const key = apiKey();
  const res = await fetch(`${base}/v1/tuning/rollback`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(key ? { "X-API-Key": key } : {})
    },
    body: JSON.stringify({ snapshot_id })
  });
  if (!res.ok) {
    throw new Error("tuning_rollback_failed");
  }
  return res.json();
}

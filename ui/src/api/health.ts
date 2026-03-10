import { apiKeyHeader, getIngestApiKey } from "./auth";

export type HealthResponse = {
  status: string;
  rules: number;
};

export type MetricsResponse = {
  uptime_seconds: number;
  total_requests: number;
  success: number;
  failures: number;
  unauthorized: number;
  payload_too_large: number;
  read_errors: number;
  schema_errors: number;
  events_in: number;
  mapping_misses: number;
  unmatched_requests: number;
  failure_rate: number;
};

export async function fetchHealth(baseUrl: string) {
  const res = await fetch(`${baseUrl}/v1/healthz`, {
    headers: apiKeyHeader(getIngestApiKey())
  });
  if (!res.ok) throw new Error("health_fetch_failed");
  const raw = (await res.json()) as any;
  return (raw?.data ?? raw) as HealthResponse;
}

export async function fetchMetrics(baseUrl: string) {
  const res = await fetch(`${baseUrl}/v1/metrics`, {
    headers: apiKeyHeader(getIngestApiKey())
  });
  if (!res.ok) throw new Error("metrics_fetch_failed");
  const raw = (await res.json()) as any;
  return (raw?.data ?? raw) as MetricsResponse;
}

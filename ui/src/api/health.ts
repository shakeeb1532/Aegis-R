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

function apiKeyHeader() {
  const key =
    (import.meta as any).env?.VITE_INGEST_API_KEY ||
    window.localStorage.getItem("ingestApiKey") ||
    window.localStorage.getItem("amanApiKey") ||
    "";
  return key ? { "X-API-Key": key } : undefined;
}

export async function fetchHealth(baseUrl: string) {
  const res = await fetch(`${baseUrl}/v1/healthz`, { headers: apiKeyHeader() });
  if (!res.ok) throw new Error("health_fetch_failed");
  const raw = (await res.json()) as any;
  return (raw?.data ?? raw) as HealthResponse;
}

export async function fetchMetrics(baseUrl: string) {
  const res = await fetch(`${baseUrl}/v1/metrics`, { headers: apiKeyHeader() });
  if (!res.ok) throw new Error("metrics_fetch_failed");
  const raw = (await res.json()) as any;
  return (raw?.data ?? raw) as MetricsResponse;
}

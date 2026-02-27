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
  const res = await fetch(`${baseUrl}/healthz`);
  if (!res.ok) throw new Error("health_fetch_failed");
  return (await res.json()) as HealthResponse;
}

export async function fetchMetrics(baseUrl: string) {
  const res = await fetch(`${baseUrl}/metrics`);
  if (!res.ok) throw new Error("metrics_fetch_failed");
  return (await res.json()) as MetricsResponse;
}

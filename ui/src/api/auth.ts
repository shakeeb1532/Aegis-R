export function getApiKey() {
  return (
    import.meta.env.VITE_API_KEY ||
    window.localStorage.getItem("amanApiKey") ||
    window.localStorage.getItem("ingestApiKey") ||
    ""
  );
}

export function getIngestApiKey() {
  return (
    (import.meta as any).env?.VITE_INGEST_API_KEY ||
    window.localStorage.getItem("ingestApiKey") ||
    window.localStorage.getItem("amanApiKey") ||
    ""
  );
}

export function apiKeyHeader(key: string) {
  return key ? { "X-API-Key": key } : undefined;
}

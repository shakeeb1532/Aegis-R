import { useEffect, useMemo, useState } from "react";
import { fetchHealth, fetchMetrics, HealthResponse, MetricsResponse } from "../api/health";

const DEFAULT_BASE = (import.meta as any).env?.VITE_INGEST_BASE_URL || "http://localhost:8080";
const STORAGE_KEY = "ingestBaseUrl";

export function IngestStatusPanel() {
  const [baseUrl, setBaseUrl] = useState(
    () => window.localStorage.getItem(STORAGE_KEY) || DEFAULT_BASE
  );
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [metrics, setMetrics] = useState<MetricsResponse | null>(null);
  const [error, setError] = useState<string>("");

  const statusLabel = useMemo(() => {
    if (!health) return "UNKNOWN";
    return health.status === "ok" ? "HEALTHY" : "ISSUE";
  }, [health]);

  const refresh = async () => {
    try {
      setError("");
      const [h, m] = await Promise.all([fetchHealth(baseUrl), fetchMetrics(baseUrl)]);
      setHealth(h);
      setMetrics(m);
    } catch (err) {
      setError("Unable to reach ingest service. Check the base URL.");
    }
  };

  useEffect(() => {
    window.localStorage.setItem(STORAGE_KEY, baseUrl);
    void refresh();
  }, [baseUrl]);

  return (
    <section className="card space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="text-xs uppercase tracking-[0.2em] text-muted">Ingest Health</p>
          <h3 className="section-title mt-2 text-xl font-semibold">Pilot System Status</h3>
        </div>
        <span
          className={`badge ${
            statusLabel === "HEALTHY" ? "border-teal text-teal" : "border-amber text-amber"
          }`}
        >
          {statusLabel}
        </span>
      </div>

      <div className="flex flex-wrap items-center gap-3">
        <input
          value={baseUrl}
          onChange={(e) => setBaseUrl(e.target.value)}
          className="w-full max-w-md rounded-xl border border-border bg-panel px-3 py-2 text-sm text-text"
          placeholder="http://localhost:8080"
        />
        <button
          onClick={refresh}
          className="rounded-full border border-border bg-panelElev px-4 py-2 text-xs uppercase tracking-[0.2em] text-muted"
        >
          Refresh
        </button>
      </div>

      {error ? (
        <div className="rounded-xl border border-red/40 bg-red/10 px-4 py-3 text-sm text-red">
          {error}
        </div>
      ) : null}

      <div className="grid gap-4 md:grid-cols-3">
        <div className="rounded-2xl border border-border bg-panelElev p-4">
          <p className="text-xs uppercase tracking-[0.2em] text-muted">Rules Loaded</p>
          <p className="mt-2 text-2xl font-semibold text-text">{health?.rules ?? "—"}</p>
        </div>
        <div className="rounded-2xl border border-border bg-panelElev p-4">
          <p className="text-xs uppercase tracking-[0.2em] text-muted">Events In</p>
          <p className="mt-2 text-2xl font-semibold text-text">{metrics?.events_in ?? "—"}</p>
        </div>
        <div className="rounded-2xl border border-border bg-panelElev p-4">
          <p className="text-xs uppercase tracking-[0.2em] text-muted">Failure Rate</p>
          <p className="mt-2 text-2xl font-semibold text-text">
            {metrics ? `${Math.round(metrics.failure_rate * 100)}%` : "—"}
          </p>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <Metric label="Total Requests" value={metrics?.total_requests} />
        <Metric label="Success" value={metrics?.success} />
        <Metric label="Schema Errors" value={metrics?.schema_errors} />
        <Metric label="Mapping Misses" value={metrics?.mapping_misses} />
      </div>
    </section>
  );
}

function Metric({ label, value }: { label: string; value?: number }) {
  return (
    <div className="rounded-2xl border border-border bg-panelElev p-4">
      <p className="text-xs uppercase tracking-[0.2em] text-muted">{label}</p>
      <p className="mt-2 text-lg font-semibold text-text">{value ?? "—"}</p>
    </div>
  );
}

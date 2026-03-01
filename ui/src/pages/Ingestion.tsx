import { useEffect, useMemo, useState } from "react";
import { SectionHeader } from "../components/SectionHeader";
import { fetchHealth, fetchMetrics, HealthResponse, MetricsResponse } from "../api/health";

const DEFAULT_BASE = (import.meta as any).env?.VITE_INGEST_BASE_URL || "http://localhost:8080";
const STORAGE_BASE = "ingestBaseUrl";
const STORAGE_KEY = "ingestApiKey";

type SchemaOption = {
  value: string;
  label: string;
  sample: string;
  kind?: string;
};

const schemaOptions: SchemaOption[] = [
  {
    value: "native",
    label: "Native Aman",
    sample: JSON.stringify(
      [
        {
          id: "evt-1",
          time: "2026-02-27T05:45:00Z",
          host: "host-1",
          user: "alice",
          type: "signin_attempt",
          details: { signInId: "signin-123", source: "entra_graph" }
        }
      ],
      null,
      2
    )
  },
  {
    value: "ecs",
    label: "ECS (Elastic Common Schema)",
    sample: JSON.stringify(
      [
        {
          "@timestamp": "2026-02-27T05:45:00Z",
          event: {
            id: "evt-2",
            kind: "event",
            action: "password_spray",
            category: ["authentication"],
            type: ["start"]
          },
          host: { name: "host-1" },
          user: { name: "alice" },
          labels: { note: "ecs test" }
        }
      ],
      null,
      2
    )
  },
  {
    value: "elastic_ecs",
    label: "Elastic ECS",
    sample: JSON.stringify(
      [
        {
          "@timestamp": "2026-02-27T05:45:00Z",
          event: { id: "evt-3", category: ["authentication"], type: ["start"] },
          host: { name: "host-1" },
          user: { name: "alice" },
          labels: { note: "elastic ecs" }
        }
      ],
      null,
      2
    )
  },
  {
    value: "ocsf",
    label: "OCSF",
    sample: JSON.stringify(
      [
        {
          event_uid: "evt-4",
          type_name: "signin_attempt",
          time: "2026-02-27T05:45:00Z",
          hostname: "host-1",
          user_name: "alice",
          attributes: { note: "ocsf test" }
        }
      ],
      null,
      2
    )
  },
  {
    value: "cim",
    label: "Splunk CIM",
    sample: JSON.stringify(
      [
        {
          _time: "2026-02-27T05:45:00Z",
          event_id: "evt-5",
          user: "alice",
          host: "host-1",
          action: "authentication",
          fields: { note: "cim test" }
        }
      ],
      null,
      2
    )
  },
  {
    value: "mde",
    label: "Microsoft Defender for Endpoint",
    kind: "deviceEvents",
    sample: JSON.stringify(
      [
        {
          id: "evt-6",
          timestamp: "2026-02-27T05:45:00Z",
          deviceName: "host-1",
          accountName: "alice",
          actionType: "SignInAttempt",
          additionalFields: { note: "mde test" }
        }
      ],
      null,
      2
    )
  },
  {
    value: "entra_signins_graph",
    label: "Entra Graph signIns",
    sample: JSON.stringify(
      {
        value: [
          {
            id: "signin-123",
            createdDateTime: "2026-02-27T05:45:00Z",
            userPrincipalName: "alice@example.com",
            userId: "user-1",
            tenantId: "tenant-1",
            ipAddress: "203.0.113.10",
            conditionalAccessStatus: "failure",
            authenticationRequirement: "singleFactorAuthentication",
            riskLevelAggregated: "high",
            riskState: "atRisk",
            status: { errorCode: 53003, failureReason: "Conditional Access blocked", additionalDetails: "" },
            deviceDetail: { deviceId: "device-1", displayName: "laptop-1", isCompliant: false, isManaged: false },
            authenticationDetails: [
              { authenticationMethod: "Password", succeeded: true, authenticationStepResultDetail: "" }
            ]
          }
        ]
      },
      null,
      2
    )
  }
];

export function Ingestion() {
  const [baseUrl, setBaseUrl] = useState(
    () => window.localStorage.getItem(STORAGE_BASE) || DEFAULT_BASE
  );
  const [apiKey, setApiKey] = useState(() => window.localStorage.getItem(STORAGE_KEY) || "");
  const [schema, setSchema] = useState(schemaOptions[0].value);
  const [payload, setPayload] = useState(schemaOptions[0].sample);
  const [kind, setKind] = useState(schemaOptions[0].kind || "");
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [metrics, setMetrics] = useState<MetricsResponse | null>(null);
  const [status, setStatus] = useState<string>("");
  const [sending, setSending] = useState(false);

  const schemaMeta = useMemo(() => schemaOptions.find((s) => s.value === schema), [schema]);
  const resolvedKind = schemaMeta?.kind || kind;

  useEffect(() => {
    window.localStorage.setItem(STORAGE_BASE, baseUrl);
  }, [baseUrl]);

  useEffect(() => {
    window.localStorage.setItem(STORAGE_KEY, apiKey);
  }, [apiKey]);

  useEffect(() => {
    if (!schemaMeta) return;
    setPayload(schemaMeta.sample);
    setKind(schemaMeta.kind || "");
  }, [schema]);

  const checkHealth = async () => {
    setStatus("Checking ingest health...");
    try {
      const [h, m] = await Promise.all([fetchHealth(baseUrl), fetchMetrics(baseUrl)]);
      setHealth(h);
      setMetrics(m);
      setStatus("Ingest reachable.");
    } catch {
      setStatus("Unable to reach ingest service. Check the base URL.");
    }
  };

  const sendPayload = async (body: string) => {
    setSending(true);
    setStatus("");
    try {
      const url = new URL(`${baseUrl}/v1/ingest`);
      url.searchParams.set("schema", schema);
      if (resolvedKind) url.searchParams.set("kind", resolvedKind);
      const res = await fetch(url.toString(), {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(apiKey ? { "X-API-Key": apiKey } : {})
        },
        body
      });
      const data = await res.json();
      const payload = data?.data ?? data;
      if (!res.ok) {
        const msg = data?.error?.message || data?.error || "Ingest failed.";
        setStatus(`Ingest failed: ${msg}`);
      } else {
        setStatus(`Ingested ${payload?.count ?? 0} events successfully.`);
        void checkHealth();
      }
    } catch (err) {
      setStatus("Ingest request failed. Check CORS, schema, or base URL.");
    } finally {
      setSending(false);
    }
  };

  const onSend = () => sendPayload(payload);

  const onUpload = async (file: File | null) => {
    if (!file) return;
    const text = await file.text();
    setPayload(text);
    void sendPayload(text);
  };

  const curlSnippet = useMemo(() => {
    const url = `${baseUrl}/ingest?schema=${schema}${resolvedKind ? `&kind=${resolvedKind}` : ""}`;
    return `curl -X POST "${url}" \\\n  -H "Content-Type: application/json" \\\n  ${
      apiKey ? `-H "X-API-Key: ${apiKey}" \\\n  ` : ""
    }-d @events.json`;
  }, [baseUrl, schema, apiKey, resolvedKind]);

  return (
    <div className="space-y-6">
      <section className="card">
        <SectionHeader
          title="Ingestion Setup"
          subtitle="Connect your data source and send a test event"
        />
        <div className="mt-4 grid gap-4 md:grid-cols-2">
          <div className="rounded-2xl border border-border bg-panelElev p-4 text-sm text-muted">
            <p className="text-xs uppercase tracking-[0.2em] text-muted">Two Ingestion Paths</p>
            <ul className="mt-3 space-y-2 text-sm text-text">
              <li>
                <span className="font-semibold text-teal">Path A (recommended):</span>{" "}
                Pull Entra sign-ins with the CLI, normalize to atomic evidence, then POST to
                <span className="text-teal"> /v1/ingest?schema=native</span>.
              </li>
              <li>
                <span className="font-semibold text-amber">Path B (server-side normalize):</span>{" "}
                Send raw Entra Graph signIns directly to
                <span className="text-amber"> /v1/ingest?schema=entra_signins_graph</span>.
              </li>
            </ul>
          </div>
          <div className="rounded-2xl border border-border bg-panelElev p-4 text-sm text-muted">
            <p className="text-xs uppercase tracking-[0.2em] text-muted">Key Clarification</p>
            <p className="mt-3 text-sm text-text">
              The ingest API does not pull from Entra. It only accepts events you POST. Use the
              CLI puller/normalizer first, or send raw Graph signIns with the special schema.
            </p>
          </div>
        </div>
        <div className="mt-6 grid gap-6 lg:grid-cols-[1.2fr_1fr]">
          <div className="space-y-4">
            <label className="text-xs uppercase tracking-[0.2em] text-muted">Ingest Base URL</label>
            <input
              value={baseUrl}
              onChange={(e) => setBaseUrl(e.target.value)}
              className="w-full rounded-xl border border-border bg-panel px-3 py-2 text-sm text-text"
              placeholder="http://localhost:8080"
            />
            <label className="text-xs uppercase tracking-[0.2em] text-muted">API Key (optional)</label>
            <input
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              className="w-full rounded-xl border border-border bg-panel px-3 py-2 text-sm text-text"
              placeholder="X-API-Key"
            />
            <div className="flex flex-wrap gap-2">
              <button
                onClick={checkHealth}
                className="rounded-full border border-border bg-panelElev px-4 py-2 text-xs uppercase tracking-[0.2em] text-muted"
              >
                Check Health
              </button>
              <span className="text-xs text-muted">{status}</span>
            </div>
            <div className="grid gap-4 md:grid-cols-3">
              <MetricCard label="Rules Loaded" value={health?.rules} />
              <MetricCard label="Events In" value={metrics?.events_in} />
              <MetricCard label="Failure Rate" value={metrics ? `${Math.round(metrics.failure_rate * 100)}%` : "—"} />
            </div>
          </div>

          <div className="rounded-2xl border border-border bg-panelElev p-4 text-sm text-muted">
            <p className="text-xs uppercase tracking-[0.2em] text-muted">Quick Curl</p>
            <pre className="mt-3 whitespace-pre-wrap text-xs text-text">{curlSnippet}</pre>
            <p className="mt-3 text-xs text-muted">
              Save your payload as <span className="text-text">events.json</span> and run the curl command above.
            </p>
          </div>
        </div>
      </section>

      <section className="card">
        <SectionHeader title="Send Test Payload" subtitle="Select a schema and post a sample event" />
        <div className="mt-6 grid gap-4 md:grid-cols-2">
          <div>
            <label className="text-xs uppercase tracking-[0.2em] text-muted">Schema</label>
            <select
              value={schema}
              onChange={(e) => setSchema(e.target.value)}
              className="mt-2 w-full rounded-xl border border-border bg-panel px-3 py-2 text-sm text-text"
            >
              {schemaOptions.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="text-xs uppercase tracking-[0.2em] text-muted">Kind (optional)</label>
            <input
              value={resolvedKind}
              onChange={(e) => setKind(e.target.value)}
              className="mt-2 w-full rounded-xl border border-border bg-panel px-3 py-2 text-sm text-text"
              placeholder="deviceEvents"
            />
          </div>
        </div>
        <textarea
          value={payload}
          onChange={(e) => setPayload(e.target.value)}
          rows={12}
          className="mt-4 w-full rounded-2xl border border-border bg-panel px-4 py-3 text-xs text-text"
        />
        <div className="mt-4 flex flex-wrap items-center gap-3">
          <button
            onClick={onSend}
            disabled={sending}
            className="rounded-full bg-teal px-4 py-2 text-xs font-semibold text-base disabled:opacity-60"
          >
            {sending ? "Sending..." : "Send Payload"}
          </button>
          <label className="rounded-full border border-border bg-panelElev px-4 py-2 text-xs uppercase tracking-[0.2em] text-muted">
            Upload JSON
            <input
              type="file"
              accept="application/json"
              className="hidden"
              onChange={(e) => onUpload(e.target.files?.[0] || null)}
            />
          </label>
          <span className="text-xs text-muted">Upload a JSON array of events for bulk ingest.</span>
        </div>
      </section>

      <section className="card">
        <SectionHeader title="Automation Tips" subtitle="Keep ingestion running without manual steps" />
        <div className="mt-4 grid gap-4 md:grid-cols-2">
          <div className="rounded-2xl border border-border bg-panelElev p-4 text-sm text-muted">
            <p className="text-xs uppercase tracking-[0.2em] text-muted">Batch mode</p>
            <p className="mt-2 text-sm text-text">
              Post JSON arrays on a schedule (cron, CI, or a small sidecar). Keep batches under 10 MB.
            </p>
          </div>
          <div className="rounded-2xl border border-border bg-panelElev p-4 text-sm text-muted">
            <p className="text-xs uppercase tracking-[0.2em] text-muted">Streaming mode</p>
            <p className="mt-2 text-sm text-text">
              For high volume, push to a queue and have a relay service call <span className="text-text">/ingest</span>.
            </p>
          </div>
        </div>
      </section>
    </div>
  );
}

function MetricCard({ label, value }: { label: string; value?: string | number }) {
  return (
    <div className="rounded-2xl border border-border bg-panelElev p-4">
      <p className="text-xs uppercase tracking-[0.2em] text-muted">{label}</p>
      <p className="mt-2 text-lg font-semibold text-text">{value ?? "—"}</p>
    </div>
  );
}

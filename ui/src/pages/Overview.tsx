import { useOverview, useGraph, useReasoning } from "../hooks/useApiData";
import { IngestStatusPanel } from "../components/IngestStatusPanel";

function metricTone(label: string) {
  const l = label.toLowerCase();
  if (l.includes("path") || l.includes("risk") || l.includes("critical")) return "text-red";
  if (l.includes("gap") || l.includes("missing")) return "text-amber";
  return "text-teal";
}

function confidenceBand(value: number) {
  if (value >= 0.8) return { label: "High", tone: "text-teal" };
  if (value >= 0.6) return { label: "Moderate", tone: "text-amber" };
  return { label: "Low", tone: "text-red" };
}

export function Overview() {
  const { data, loading: overviewLoading } = useOverview();
  const { data: reasoning, loading: reasoningLoading } = useReasoning();
  const { data: graph, loading: graphLoading } = useGraph();
  const loading = overviewLoading || reasoningLoading || graphLoading;

  const verdictCounts = reasoning.reduce(
    (acc, item) => {
      acc.total += 1;
      const v = item.verdict.toUpperCase();
      acc[v] = (acc[v] || 0) + 1;
      return acc;
    },
    { total: 0 } as Record<string, number>
  );

  const feasible = (verdictCounts.POSSIBLE || 0) + (verdictCounts.CONFIRMED || 0);
  const incomplete = verdictCounts.INCOMPLETE || 0;
  const impossible = verdictCounts.IMPOSSIBLE || 0;

  const funnelStages = [
    { label: "Total Findings", count: verdictCounts.total, tone: "text-muted" },
    { label: "Feasible", count: feasible, tone: "text-teal" },
    { label: "Incomplete", count: incomplete, tone: "text-amber" },
    { label: "Impossible", count: impossible, tone: "text-red" }
  ];

  const gapCounts = reasoning.reduce((acc, item) => {
    item.gaps.forEach((gap) => {
      acc[gap] = (acc[gap] || 0) + 1;
    });
    return acc;
  }, {} as Record<string, number>);
  const gapEntries = Object.entries(gapCounts).sort((a, b) => b[1] - a[1]).slice(0, 6);
  const maxGap = gapEntries[0]?.[1] || 1;

  const identityTimeline = (graph.progression || [])
    .filter((p) => p.stage.toLowerCase().includes("identity") || p.action.toLowerCase().includes("signin"))
    .slice(0, 6);

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between rounded-2xl border border-border bg-panel px-4 py-3 text-xs text-muted">
        <span className="uppercase tracking-[0.2em]">Overview Sync</span>
        <span className={`badge ${loading ? "border-amber/40 text-amber" : "border-teal/40 text-teal"}`}>
          {loading ? "Syncing" : "Live"}
        </span>
      </div>
      <IngestStatusPanel />
      <section className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        {data.kpis.map((kpi) => (
          <article key={kpi.label} className="rounded-2xl border border-border bg-panel p-5">
            <p className="text-xs uppercase tracking-[0.12em] text-muted">{kpi.label}</p>
            <p className={`mt-3 text-4xl font-semibold ${metricTone(kpi.label)}`}>{kpi.value}</p>
            <p className="mt-2 text-sm text-muted">{kpi.sub}</p>
          </article>
        ))}
      </section>

      <section className="grid gap-4 xl:grid-cols-[1.2fr_1fr]">
        <article className="rounded-2xl border border-border bg-panel p-5">
          <div className="flex items-center justify-between gap-4">
            <div>
              <p className="text-xs uppercase tracking-[0.12em] text-muted">Current Decision</p>
              <h2 className="section-title mt-2 text-2xl font-semibold">{data.headline.title}</h2>
            </div>
            <span className="rounded-full border border-border bg-panelElev px-3 py-1 text-xs uppercase tracking-wide text-muted">
              {data.headline.verdict}
            </span>
          </div>
          <p className="mt-4 text-sm text-muted">{data.headline.summary}</p>
          <div className="mt-4 grid gap-3 md:grid-cols-2">
            <div className="rounded-xl border border-border bg-panelElev p-3">
              <p className="text-xs uppercase tracking-wide text-muted">Confidence Band</p>
              <p className={`mt-1 text-2xl font-semibold ${confidenceBand(data.headline.confidence).tone}`}>
                {confidenceBand(data.headline.confidence).label}
              </p>
            </div>
            <div className="rounded-xl border border-border bg-panelElev p-3">
              <p className="text-xs uppercase tracking-wide text-muted">Updated</p>
              <p className="mt-1 text-sm text-text">{data.headline.updated}</p>
            </div>
          </div>
        </article>

        <article className="rounded-2xl border border-border bg-panel p-5">
          <p className="text-xs uppercase tracking-[0.12em] text-muted">Top Evidence Gaps</p>
          <ul className="mt-3 space-y-2 text-sm text-muted">
            {data.evidence_gaps.slice(0, 6).map((gap) => (
              <li key={gap} className="flex items-start gap-2">
                <span className="mt-1 h-1.5 w-1.5 rounded-full bg-amber" />
                {gap}
              </li>
            ))}
          </ul>
        </article>
      </section>

      <section className="grid gap-4 xl:grid-cols-2">
        <article className="rounded-2xl border border-border bg-panel p-5">
          <p className="text-xs uppercase tracking-[0.12em] text-muted">Drift Signals</p>
          <ul className="mt-3 space-y-2 text-sm text-muted">
            {data.drift_signals.slice(0, 8).map((signal) => (
              <li key={signal} className="flex items-start gap-2">
                <span className="mt-1 h-1.5 w-1.5 rounded-full bg-purple" />
                {signal}
              </li>
            ))}
          </ul>
        </article>

        <article className="rounded-2xl border border-border bg-panel p-5">
          <p className="text-xs uppercase tracking-[0.12em] text-muted">Suggested Human Actions</p>
          <ul className="mt-3 space-y-2 text-sm text-muted">
            {data.suggested_actions.slice(0, 8).map((action) => (
              <li key={action} className="rounded-lg border border-border bg-panelElev px-3 py-2 text-text">
                {action}
              </li>
            ))}
          </ul>
        </article>
      </section>

      <section className="grid gap-4 xl:grid-cols-2">
        <article className="rounded-2xl border border-border bg-panel p-5">
          <p className="text-xs uppercase tracking-[0.12em] text-muted">Decision Funnel</p>
          <div className="mt-4 space-y-3">
            {funnelStages.map((stage) => {
              const width = verdictCounts.total ? (stage.count / verdictCounts.total) * 100 : 0;
              return (
                <div key={stage.label} className="space-y-1">
                  <div className="flex items-center justify-between text-xs text-muted">
                    <span>{stage.label}</span>
                    <span className={stage.tone}>{stage.count}</span>
                  </div>
                  <div className="h-2 w-full rounded-full bg-panelElev">
                    <div
                      className="h-2 rounded-full bg-teal/60"
                      style={{ width: `${Math.max(6, width)}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </article>

        <article className="rounded-2xl border border-border bg-panel p-5">
          <p className="text-xs uppercase tracking-[0.12em] text-muted">Evidence Coverage Heatmap</p>
          {gapEntries.length === 0 ? (
            <p className="mt-4 text-sm text-muted">No evidence gaps reported.</p>
          ) : (
            <div className="mt-4 grid gap-3 md:grid-cols-2">
              {gapEntries.map(([gap, count]) => {
                const intensity = count / maxGap;
                return (
                  <div
                    key={gap}
                    className="rounded-xl border border-border px-3 py-3 text-sm text-text"
                    style={{ backgroundColor: `rgba(245,158,11,${0.15 + intensity * 0.55})` }}
                  >
                    <div className="text-xs uppercase text-muted">Missing</div>
                    <div className="mt-1 font-semibold">{gap}</div>
                    <div className="mt-1 text-xs text-muted">{count} occurrences</div>
                  </div>
                );
              })}
            </div>
          )}
        </article>
      </section>

      <section className="rounded-2xl border border-border bg-panel p-5">
        <p className="text-xs uppercase tracking-[0.12em] text-muted">Identity Risk Timeline</p>
        {identityTimeline.length === 0 ? (
          <p className="mt-4 text-sm text-muted">No identity progression events yet.</p>
        ) : (
          <div className="mt-4 space-y-4">
            <svg viewBox="0 0 900 120" className="h-[120px] w-full">
              <line x1="40" y1="60" x2="860" y2="60" stroke="#233140" strokeWidth="2" />
              {identityTimeline.map((item, idx) => {
                const x = 60 + idx * 120;
                return (
                  <g key={`${item.time}-${idx}`}>
                    <circle cx={x} cy={60} r="10" fill="#27beff" />
                    <text x={x} y={86} textAnchor="middle" fontSize="10" fill="#9fb3c8">
                      {item.action}
                    </text>
                    <text x={x} y={102} textAnchor="middle" fontSize="9" fill="#64748b">
                      {item.time.split(" ")[1] || item.time}
                    </text>
                  </g>
                );
              })}
            </svg>
            <div className="grid gap-2 md:grid-cols-2">
              {identityTimeline.map((item, idx) => (
                <div key={`${item.time}-${idx}`} className="rounded-xl border border-border bg-panelElev px-3 py-2 text-sm text-text">
                  <div className="text-xs uppercase text-muted">{item.stage}</div>
                  <div className="font-semibold">{item.action}</div>
                  <div className="text-xs text-muted">{item.time} · {item.principal || "unknown"}</div>
                </div>
              ))}
            </div>
          </div>
        )}
      </section>
    </div>
  );
}

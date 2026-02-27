import { useOverview } from "../hooks/useApiData";
import { IngestStatusPanel } from "../components/IngestStatusPanel";

function metricTone(label: string) {
  const l = label.toLowerCase();
  if (l.includes("path") || l.includes("risk") || l.includes("critical")) return "text-red";
  if (l.includes("gap") || l.includes("missing")) return "text-amber";
  return "text-teal";
}

export function Overview() {
  const data = useOverview();

  return (
    <div className="space-y-5">
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
              <p className="text-xs uppercase tracking-wide text-muted">Confidence</p>
              <p className="mt-1 text-2xl font-semibold text-text">{Math.round(data.headline.confidence * 100)}%</p>
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
    </div>
  );
}

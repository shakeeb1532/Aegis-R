import { KpiCard } from "../components/KpiCard";
import { SectionHeader } from "../components/SectionHeader";
import { VerdictPill } from "../components/VerdictPill";
import { ConfidenceMeter } from "../components/ConfidenceMeter";
import { driftSignals, evidenceGaps, overviewKpis, reasoningSamples } from "../data/sample";

export function Overview() {
  const headline = reasoningSamples[1];

  return (
    <div className="space-y-8">
      <section className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        {overviewKpis.map((kpi) => (
          <KpiCard key={kpi.label} label={kpi.label} value={kpi.value} sub={kpi.sub} />
        ))}
      </section>

      <section className="grid gap-6 xl:grid-cols-[1.3fr_1fr]">
        <div className="card-elev space-y-6">
          <SectionHeader title="Current Verdict" subtitle="Causal reasoning snapshot" />
          <div className="flex items-start justify-between gap-6">
            <div className="space-y-4">
              <VerdictPill verdict={headline.verdict} />
              <div>
                <h3 className="section-title text-lg font-semibold">{headline.title}</h3>
                <p className="mt-2 text-sm text-muted">{headline.summary}</p>
              </div>
              <div className="text-xs text-muted">Last update: {headline.updated}</div>
            </div>
            <div className="w-48 rounded-2xl border border-border bg-panel p-4">
              <p className="text-xs uppercase tracking-wide text-muted">Confidence</p>
              <p className="mt-2 text-2xl font-semibold">{Math.round(headline.confidence * 100)}%</p>
              <ConfidenceMeter value={headline.confidence} />
              <p className="mt-3 text-xs text-muted">Decay timer: 2h 18m</p>
            </div>
          </div>
        </div>
        <div className="card space-y-4">
          <SectionHeader title="Drift Signals" subtitle="New access paths detected" />
          <ul className="space-y-3 text-sm text-muted">
            {driftSignals.map((item) => (
              <li key={item} className="flex items-start gap-3">
                <span className="mt-1 h-2 w-2 rounded-full bg-amber"></span>
                {item}
              </li>
            ))}
          </ul>
        </div>
      </section>

      <section className="grid gap-6 xl:grid-cols-[1fr_1fr]">
        <div className="card space-y-4">
          <SectionHeader title="Top Evidence Gaps" subtitle="Blocks for CONFIRMED verdicts" />
          <ul className="space-y-3 text-sm text-muted">
            {evidenceGaps.map((gap) => (
              <li key={gap} className="flex items-start gap-3">
                <span className="mt-1 h-2 w-2 rounded-full bg-amber"></span>
                {gap}
              </li>
            ))}
          </ul>
        </div>
        <div className="card space-y-4">
          <SectionHeader title="Suggested Actions" subtitle="Human sign-off required" />
          <div className="space-y-3 text-sm text-muted">
            <div className="rounded-xl border border-border bg-panel-elev p-4">
              <p className="text-sm text-text">Approve elevated risk hold for svc-backup</p>
              <p className="mt-2 text-xs text-muted">Evidence: role change + OAuth consent. Confidence 0.82.</p>
            </div>
            <div className="rounded-xl border border-border bg-panel-elev p-4">
              <p className="text-sm text-text">Request device posture for new geo sign-in</p>
              <p className="mt-2 text-xs text-muted">Evidence gaps: no MFA challenge, no device attestation.</p>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}

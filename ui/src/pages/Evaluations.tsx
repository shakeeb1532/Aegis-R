import { SectionHeader } from "../components/SectionHeader";
import { useEvaluations } from "../hooks/useApiData";

export function Evaluations() {
  const data = useEvaluations();
  return (
    <div className="space-y-6">
      <section className="card">
        <SectionHeader title="Evaluations" subtitle="Baselines and regression notes" />
        <div className="mt-6 grid gap-4 md:grid-cols-3">
          {data.map((item) => (
            <div key={item.label} className="rounded-2xl border border-border bg-panelElev p-5">
              <p className="text-xs uppercase tracking-wide text-muted">{item.label}</p>
              <p className="mt-3 text-2xl font-semibold">{item.value}</p>
              <p className="mt-2 text-xs text-muted">Δ {item.delta}</p>
              <p className="mt-4 text-xs text-muted">{item.note}</p>
            </div>
          ))}
        </div>
        <div className="mt-6 rounded-2xl border border-border bg-panelElev p-5 text-sm text-muted">
          Regression notes: Increased false-positive suppression for identity anomalies. Monitoring edge cases in
          incomplete verdicts.
        </div>
      </section>
    </div>
  );
}

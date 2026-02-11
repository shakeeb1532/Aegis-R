import { SectionHeader } from "../components/SectionHeader";
import { VerdictPill } from "../components/VerdictPill";
import { useQueue } from "../hooks/useApiData";

export function Queue() {
  const data = useQueue();
  return (
    <div className="space-y-6">
      <section className="card">
        <SectionHeader title="Reasoning Queue" subtitle="Analyst review workbench" />
        <div className="mt-6 grid gap-4">
          {data.map((item) => (
            <div key={item.id} className="rounded-2xl border border-border bg-panelElev p-5">
              <div className="flex items-start justify-between gap-6">
                <div>
                  <p className="text-xs uppercase tracking-[0.2em] text-muted">{item.id}</p>
                  <h3 className="section-title mt-2 text-lg font-semibold">{item.rule}</h3>
                  <p className="mt-2 text-xs text-muted">
                    Principal: {item.principal} · Asset: {item.asset} · Updated {item.updated}
                  </p>
                </div>
                <VerdictPill verdict={item.verdict} />
              </div>
              <div className="mt-4 grid gap-4 md:grid-cols-2">
                <div>
                  <p className="text-xs uppercase tracking-wide text-muted">Evidence</p>
                  <ul className="mt-2 space-y-1 text-sm text-muted">
                    {item.evidence.map((e) => (
                      <li key={e}>• {e}</li>
                    ))}
                  </ul>
                </div>
                <div>
                  <p className="text-xs uppercase tracking-wide text-muted">Evidence Gaps</p>
                  <ul className="mt-2 space-y-1 text-sm text-muted">
                    {item.gaps.map((e) => (
                      <li key={e}>• {e}</li>
                    ))}
                  </ul>
                </div>
              </div>
              <div className="mt-4 flex gap-3">
                <button className="rounded-full border border-border px-4 py-2 text-xs text-muted">
                  Flag for follow-up
                </button>
                <button className="rounded-full bg-purple px-4 py-2 text-xs font-semibold text-white">
                  Request approval
                </button>
              </div>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}

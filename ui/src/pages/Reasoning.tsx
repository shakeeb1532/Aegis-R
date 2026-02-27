import { SectionHeader } from "../components/SectionHeader";
import { VerdictPill } from "../components/VerdictPill";
import { useReasoning } from "../hooks/useApiData";

function confidenceBand(value: number) {
  if (value >= 0.8) return { label: "High", tone: "text-teal" };
  if (value >= 0.6) return { label: "Moderate", tone: "text-amber" };
  return { label: "Low", tone: "text-red" };
}

function factorBand(value: number) {
  if (value >= 0.8) return "High";
  if (value >= 0.6) return "Moderate";
  return "Low";
}

export function Reasoning() {
  const data = useReasoning();
  if (!data || data.length === 0) {
    return (
      <div className="card">
        <SectionHeader title="Reasoning" subtitle="No reasoning results available" />
        <p className="mt-4 text-sm text-muted">
          The API did not return any reasoning records. Verify that `serve-api` is running and that
          `data/report.json` has results.
        </p>
      </div>
    );
  }
  return (
    <div className="space-y-6">
      {data.map((item) => (
        <section key={item.id} className="card-elev space-y-6">
          <div className="flex items-start justify-between gap-6">
            <div>
              <p className="text-xs uppercase tracking-[0.2em] text-muted">{item.id}</p>
              <h2 className="section-title mt-2 text-xl font-semibold">{item.title}</h2>
              <p className="mt-2 text-sm text-muted">{item.summary}</p>
            </div>
            <VerdictPill verdict={item.verdict} />
          </div>
          <div className="grid gap-6 md:grid-cols-2">
            <div className="space-y-3">
              <SectionHeader title="Evidence Used" />
              <ul className="space-y-2 text-sm text-muted">
                {item.evidence.map((e) => (
                  <li key={e} className="flex items-start gap-3">
                    <span className="mt-1 h-2 w-2 rounded-full bg-teal"></span>
                    {e}
                  </li>
                ))}
              </ul>
            </div>
            <div className="space-y-3">
              <SectionHeader title="Evidence Missing" />
              <ul className="space-y-2 text-sm text-muted">
                {item.gaps.map((e) => (
                  <li key={e} className="flex items-start gap-3">
                    <span className="mt-1 h-2 w-2 rounded-full bg-amber"></span>
                    {e}
                  </li>
                ))}
              </ul>
            </div>
          </div>
          <div className="grid gap-6 md:grid-cols-[1.2fr_1fr]">
            <div className="space-y-3">
              <SectionHeader title="Next Likely Actions" />
              <ul className="space-y-2 text-sm text-muted">
                {item.nextMoves.map((e) => (
                  <li key={e} className="flex items-start gap-3">
                    <span className="mt-1 h-2 w-2 rounded-full bg-purple"></span>
                    {e}
                  </li>
                ))}
              </ul>
            </div>
            <div className="space-y-3">
              <SectionHeader title="Confidence + Decay" />
              <div className="rounded-xl border border-border bg-panel p-4">
                <p className="text-xs uppercase tracking-wide text-muted">Confidence Band</p>
                <p className={`mt-2 text-2xl font-semibold ${confidenceBand(item.confidence).tone}`}>
                  {confidenceBand(item.confidence).label}
                </p>
                <p className="mt-3 text-xs text-muted">Decay timer: 1h 32m</p>
              </div>
              {item.confidence_factors && (
                <div className="rounded-xl border border-border bg-panel p-4 text-sm text-muted">
                  <SectionHeader title="Confidence Rationale" />
                  <div className="mt-3 space-y-2">
                    <p>
                      Evidence coverage:{" "}
                      <span className="text-text">
                        {item.confidence_factors.evidence_present} of {item.confidence_factors.evidence_total}
                      </span>
                    </p>
                    <p>
                      Recency: <span className="text-text">{factorBand(item.confidence_factors.recency)}</span>
                    </p>
                    <p>
                      Corroboration:{" "}
                      <span className="text-text">
                        {item.confidence_factors.supporting_events} supporting events
                      </span>
                    </p>
                    <p className="text-xs text-muted">
                      Score derived from coverage + recency + corroboration. Not a probability.
                    </p>
                  </div>
                </div>
              )}
            </div>
          </div>
        </section>
      ))}
    </div>
  );
}

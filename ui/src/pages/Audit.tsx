import { SectionHeader } from "../components/SectionHeader";
import { useAudit } from "../hooks/useApiData";

export function Audit() {
  const data = useAudit();
  return (
    <div className="space-y-6">
      <section className="card">
        <SectionHeader title="Audit & Evidence" subtitle="Replayable reasoning chain" />
        <div className="mt-6 space-y-4">
          {data.map((item) => (
            <div key={item.id} className="rounded-2xl border border-border bg-panelElev p-5">
              <div className="flex items-start justify-between">
                <div>
                  <p className="text-xs uppercase tracking-[0.2em] text-muted">{item.id}</p>
                  <p className="mt-2 text-sm text-muted">{item.summary}</p>
                </div>
                <div className="text-right text-xs text-muted">
                  <p>{item.timestamp}</p>
                  <p>Signer: {item.signer}</p>
                </div>
              </div>
              <div className="mt-4 flex gap-3">
                <button className="rounded-full border border-border px-4 py-2 text-xs text-muted">
                  View evidence
                </button>
                <button className="rounded-full border border-border px-4 py-2 text-xs text-muted">
                  Download audit artifact
                </button>
              </div>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}

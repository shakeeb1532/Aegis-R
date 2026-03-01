import { SectionHeader } from "../components/SectionHeader";
import { useGovernance } from "../hooks/useApiData";

export function Governance() {
  const data = useGovernance();
  const statusCounts = data.reduce((acc, item) => {
    const key = item.status || "unknown";
    acc[key] = (acc[key] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);
  const statusEntries = Object.entries(statusCounts);
  const maxCount = Math.max(1, ...statusEntries.map(([, count]) => count));
  return (
    <div className="space-y-6">
      <section className="card">
        <SectionHeader title="Governance" subtitle="Signed approvals and trust changes" />
        <div className="mt-6 rounded-2xl border border-border bg-panelElev p-5">
          <p className="text-xs uppercase tracking-[0.12em] text-muted">Human Oversight</p>
          <div className="mt-4 space-y-3">
            {statusEntries.map(([status, count]) => (
              <div key={status} className="space-y-1">
                <div className="flex items-center justify-between text-xs text-muted">
                  <span>{status.replaceAll("_", " ")}</span>
                  <span className="text-text">{count}</span>
                </div>
                <div className="h-2 w-full rounded-full bg-panel">
                  <div
                    className="h-2 rounded-full bg-purple/70"
                    style={{ width: `${Math.max(6, (count / maxCount) * 100)}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
        <div className="mt-6 grid gap-4">
          {data.map((approval) => (
            <div key={approval.id} className="rounded-2xl border border-border bg-panelElev p-5">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-xs uppercase tracking-[0.2em] text-muted">{approval.id}</p>
                  <h3 className="section-title mt-2 text-lg font-semibold">{approval.scope}</h3>
                  <p className="mt-2 text-xs text-muted">Approver: {approval.approver}</p>
                  {approval.template_id && (
                    <p className="mt-2 text-xs text-muted">
                      Template:{" "}
                      <span className="inline-flex rounded-full border border-border px-2 py-0.5 text-[10px] uppercase tracking-[0.2em]">
                        {approval.template_id}
                      </span>
                    </p>
                  )}
                </div>
                <div className="text-right">
                  <span className="badge border-purple text-purple">{approval.status}</span>
                  <p className="mt-2 text-xs text-muted">Expires {approval.expires}</p>
                </div>
              </div>
              <div className="mt-4 flex gap-3">
                <button className="rounded-full border border-border px-4 py-2 text-xs text-muted">
                  Download signed artifact
                </button>
                <button className="rounded-full bg-purple px-4 py-2 text-xs font-semibold text-white">
                  Add second approval
                </button>
              </div>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}

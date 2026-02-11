import { SectionHeader } from "../components/SectionHeader";
import { approvals } from "../data/sample";

export function Governance() {
  return (
    <div className="space-y-6">
      <section className="card">
        <SectionHeader title="Governance" subtitle="Signed approvals and trust changes" />
        <div className="mt-6 grid gap-4">
          {approvals.map((approval) => (
            <div key={approval.id} className="rounded-2xl border border-border bg-panel-elev p-5">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-xs uppercase tracking-[0.2em] text-muted">{approval.id}</p>
                  <h3 className="section-title mt-2 text-lg font-semibold">{approval.scope}</h3>
                  <p className="mt-2 text-xs text-muted">Approver: {approval.approver}</p>
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

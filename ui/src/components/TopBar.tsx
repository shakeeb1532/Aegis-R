export function TopBar() {
  return (
    <div className="flex items-center justify-between border-b border-border bg-panel px-8 py-4">
      <div>
        <p className="text-xs uppercase tracking-[0.2em] text-muted">Live reasoning state</p>
        <h2 className="section-title text-lg font-semibold">Identity & SaaS Access</h2>
      </div>
      <div className="flex items-center gap-3">
        <button className="rounded-full border border-border px-4 py-2 text-xs text-muted">
          Export Evidence
        </button>
        <button className="rounded-full bg-purple px-4 py-2 text-xs font-semibold text-white">
          Request Approval
        </button>
      </div>
    </div>
  );
}

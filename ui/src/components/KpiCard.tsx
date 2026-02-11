export function KpiCard({ label, value, sub }: { label: string; value: string; sub: string }) {
  return (
    <div className="card kpi">
      <span className="text-xs uppercase tracking-wide text-muted">{label}</span>
      <span className="kpi-value">{value}</span>
      <span className="text-xs text-muted">{sub}</span>
    </div>
  );
}

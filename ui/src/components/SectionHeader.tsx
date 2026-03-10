type StatusTone = "live" | "syncing" | "idle";

export function SectionHeader({
  title,
  subtitle,
  status
}: {
  title: string;
  subtitle?: string;
  status?: { label: string; tone?: StatusTone };
}) {
  const tone =
    status?.tone === "live"
      ? "border-teal/40 text-teal"
      : status?.tone === "syncing"
      ? "border-amber/40 text-amber"
      : "border-border text-muted";
  return (
    <div className="flex items-center justify-between">
      <div>
        <h2 className="section-title text-xl font-semibold">{title}</h2>
        {subtitle ? <p className="text-sm text-muted">{subtitle}</p> : null}
      </div>
      {status ? <span className={`badge ${tone}`}>{status.label}</span> : null}
    </div>
  );
}

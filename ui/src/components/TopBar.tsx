export function TopBar() {
  const now = new Date().toLocaleString("en-AU", {
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false
  });

  return (
    <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border bg-panel px-6 py-4 md:px-8">
      <div className="rounded-2xl border border-teal/30 bg-panelElev px-4 py-3 text-sm font-semibold text-teal">
        Signed Integrity: Verified by Blackbox
      </div>
      <div className="flex items-center gap-4 text-sm">
        <span className="text-[#23b1ff]">(◉) AMAN-HRLKP4XG</span>
        <span className="text-muted">{now}</span>
      </div>
    </div>
  );
}

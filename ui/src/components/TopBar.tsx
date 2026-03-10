import { useHeader } from "../hooks/useApiData";

export function TopBar() {
  const { data: header } = useHeader();
  const now = new Date().toLocaleString("en-AU", {
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false
  });

  const integrity = header.integrity || "unknown";
  const integrityLabel =
    integrity === "verified"
      ? "Signed Integrity: Verified"
      : integrity === "broken"
      ? "Integrity: Chain Broken"
      : "Signed Integrity: Unknown";
  const integrityClass =
    integrity === "verified"
      ? "border-teal/30 bg-panelElev text-teal"
      : integrity === "broken"
      ? "border-red/40 bg-red/10 text-red"
      : "border-border bg-panelElev text-muted";

  return (
    <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border bg-panel px-6 py-4 md:px-8">
      <div
        className={`rounded-2xl border px-4 py-3 text-sm font-semibold ${integrityClass}`}
        title={header.integrity_note || ""}
      >
        {integrityLabel}
      </div>
      <div className="flex items-center gap-4 text-sm">
        <span className="text-[#23b1ff]">(◉) {header.session_id || "AMAN-LOCAL"}</span>
        <span className="text-muted">{now}</span>
      </div>
    </div>
  );
}

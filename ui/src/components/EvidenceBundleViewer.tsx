import { useMemo, useState } from "react";
import JSZip from "jszip";

const emptySummary = {
  report_id: "",
  generated_at: "",
  verdicts: [] as string[],
  key_findings: [] as string[],
  evidence_gaps: [] as string[],
  controls_linked: [] as string[],
  dual_approval_required: false,
  dual_approved: false,
  bundle_verified: false,
};

type Summary = typeof emptySummary & Record<string, any>;

export function EvidenceBundleViewer() {
  const [summary, setSummary] = useState<Summary | null>(null);
  const [html, setHtml] = useState<string>("");
  const [error, setError] = useState<string>("");

  const summaryDetails = useMemo(() => {
    if (!summary) return [] as string[];
    const details = [] as string[];
    if (summary.report_id) details.push(`Report ID: ${summary.report_id}`);
    if (summary.generated_at) details.push(`Generated: ${summary.generated_at}`);
    return details;
  }, [summary]);

  const handleSummaryUpload = (file?: File | null) => {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      try {
        const parsed = JSON.parse(String(reader.result));
        setSummary({ ...emptySummary, ...parsed });
        setError("");
      } catch (err) {
        setError("Summary JSON could not be parsed.");
      }
    };
    reader.readAsText(file);
  };

  const handleReportUpload = (file?: File | null) => {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      setHtml(String(reader.result));
      setError("");
    };
    reader.readAsText(file);
  };

  const handleZipUpload = async (file?: File | null) => {
    if (!file) return;
    try {
      const zip = await JSZip.loadAsync(file);
      let summaryText = "";
      let htmlText = "";
      for (const name of Object.keys(zip.files)) {
        if (name.endsWith("summary.json")) {
          summaryText = await zip.files[name].async("string");
        } else if (name.endsWith("report.html")) {
          htmlText = await zip.files[name].async("string");
        }
      }
      if (summaryText) {
        const parsed = JSON.parse(summaryText);
        setSummary({ ...emptySummary, ...parsed });
      }
      if (htmlText) {
        setHtml(htmlText);
      }
      if (!summaryText && !htmlText) {
        setError("Bundle missing summary.json or report.html.");
      } else {
        setError("");
      }
    } catch (err) {
      setError("Unable to read the bundle. Ensure it's a valid evidence zip.");
    }
  };

  return (
    <section className="card space-y-6">
      <div>
        <p className="text-xs uppercase tracking-[0.2em] text-muted">Evidence Bundle Viewer</p>
        <h2 className="section-title mt-2 text-xl font-semibold">Load Summary + Report</h2>
        <p className="mt-2 text-sm text-muted">
          Upload <span className="text-text">summary.json</span> and <span className="text-text">report.html</span> from an Aman evidence bundle.
        </p>
      </div>

      {error ? (
        <div className="rounded-xl border border-red/40 bg-red/10 px-4 py-3 text-sm text-red">
          {error}
        </div>
      ) : null}

      <div className="grid gap-4 md:grid-cols-3">
        <label className="flex flex-col gap-3 rounded-2xl border border-border bg-panelElev px-4 py-4">
          <span className="text-xs uppercase tracking-[0.2em] text-muted">Evidence Bundle (ZIP)</span>
          <input
            type="file"
            accept=".zip,application/zip"
            onChange={(e) => void handleZipUpload(e.target.files?.[0])}
            className="text-sm text-muted file:mr-4 file:rounded-full file:border file:border-border file:bg-panel file:px-3 file:py-1 file:text-xs file:uppercase file:tracking-[0.2em]"
          />
          <span className="text-xs text-muted">evidence.zip</span>
        </label>
        <label className="flex flex-col gap-3 rounded-2xl border border-border bg-panelElev px-4 py-4">
          <span className="text-xs uppercase tracking-[0.2em] text-muted">Summary JSON</span>
          <input
            type="file"
            accept="application/json"
            onChange={(e) => handleSummaryUpload(e.target.files?.[0])}
            className="text-sm text-muted file:mr-4 file:rounded-full file:border file:border-border file:bg-panel file:px-3 file:py-1 file:text-xs file:uppercase file:tracking-[0.2em]"
          />
          <span className="text-xs text-muted">summary.json</span>
        </label>

        <label className="flex flex-col gap-3 rounded-2xl border border-border bg-panelElev px-4 py-4">
          <span className="text-xs uppercase tracking-[0.2em] text-muted">Report HTML</span>
          <input
            type="file"
            accept="text/html"
            onChange={(e) => handleReportUpload(e.target.files?.[0])}
            className="text-sm text-muted file:mr-4 file:rounded-full file:border file:border-border file:bg-panel file:px-3 file:py-1 file:text-xs file:uppercase file:tracking-[0.2em]"
          />
          <span className="text-xs text-muted">report.html</span>
        </label>
      </div>

      {summary ? (
        <div className="grid gap-4 xl:grid-cols-[1.2fr_1fr]">
          <div className="rounded-2xl border border-border bg-panelElev p-5">
            <p className="text-xs uppercase tracking-[0.2em] text-muted">Summary</p>
            <ul className="mt-3 space-y-1 text-sm text-text">
              {summaryDetails.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>
            <div className="mt-4 grid gap-3 md:grid-cols-2">
              <div className="rounded-xl border border-border bg-panel px-3 py-2">
                <p className="text-xs text-muted">Bundle Verified</p>
                <p className="text-sm text-text">{summary.bundle_verified ? "Yes" : "No"}</p>
              </div>
              <div className="rounded-xl border border-border bg-panel px-3 py-2">
                <p className="text-xs text-muted">Dual Approval</p>
                <p className="text-sm text-text">
                  {summary.dual_approval_required ? (summary.dual_approved ? "Approved" : "Required") : "Not Required"}
                </p>
              </div>
            </div>
          </div>

          <div className="rounded-2xl border border-border bg-panelElev p-5">
            <p className="text-xs uppercase tracking-[0.2em] text-muted">Key Findings</p>
            <ul className="mt-3 space-y-2 text-sm text-muted">
              {(summary.key_findings || []).slice(0, 6).map((item: string) => (
                <li key={item} className="rounded-lg border border-border bg-panel px-3 py-2 text-text">
                  {item}
                </li>
              ))}
            </ul>
          </div>
        </div>
      ) : null}

      {html ? (
        <div className="rounded-2xl border border-border bg-panelElev p-3">
          <iframe
            title="Aman Evidence Report"
            className="h-[520px] w-full rounded-xl bg-white"
            sandbox="allow-same-origin"
            srcDoc={html}
          />
        </div>
      ) : (
        <div className="rounded-2xl border border-border bg-panelElev p-4 text-sm text-muted">
          Upload <span className="text-text">report.html</span> to preview the human‑readable evidence report here.
        </div>
      )}
    </section>
  );
}

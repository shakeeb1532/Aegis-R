import { SectionHeader } from "../components/SectionHeader";
import { EvidenceBundleViewer } from "../components/EvidenceBundleViewer";
import { useAudit } from "../hooks/useApiData";
import { apiHeaders, getApiBase } from "../api/client";

async function downloadAuditLog() {
  const res = await fetch(`${getApiBase()}/v1/audit/log`, {
    headers: apiHeaders()
  });
  if (!res.ok) {
    throw new Error("Audit log unavailable");
  }
  const text = await res.text();
  const blob = new Blob([text], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "audit.log";
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

export function Audit() {
  const { data, loading } = useAudit();
  return (
    <div className="space-y-6">
      <EvidenceBundleViewer />
      <section className="card">
        <SectionHeader
          title="Audit & Evidence"
          subtitle="Replayable reasoning chain"
          status={{ label: loading ? "Syncing" : "Live", tone: loading ? "syncing" : "live" }}
        />
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
                <button
                  className="rounded-full border border-border px-4 py-2 text-xs text-muted"
                  onClick={() => {
                    document.getElementById("evidence-bundle-viewer")?.scrollIntoView({ behavior: "smooth" });
                  }}
                >
                  View evidence
                </button>
                <button
                  className="rounded-full border border-border px-4 py-2 text-xs text-muted"
                  onClick={() => void downloadAuditLog().catch(() => window.alert("Audit log unavailable."))}
                >
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

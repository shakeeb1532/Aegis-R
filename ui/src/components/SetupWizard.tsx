import { useEffect, useState } from "react";

const steps = [
  {
    title: "Connect identity sources",
    body: "Link Okta, Entra ID, M365, and Google Workspace to start ingesting identity events."
  },
  {
    title: "Validate schema",
    body: "Run a schema check to confirm principal, device, IP, and action fields are present."
  },
  {
    title: "Baseline reasoning",
    body: "Generate a first-run baseline so evidence gaps and drift are tracked immediately."
  },
  {
    title: "Review pilot report",
    body: "Download the pilot-ready report with verdicts, evidence gaps, and governance decisions."
  }
];

export function SetupWizard() {
  const [open, setOpen] = useState(false);
  const [step, setStep] = useState(0);

  useEffect(() => {
    const dismissed = window.localStorage.getItem("wizardDismissed");
    if (!dismissed) {
      setOpen(true);
    }
  }, []);

  if (!open) {
    return null;
  }

  const current = steps[step];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-6">
      <div className="w-full max-w-lg rounded-2xl border border-border bg-panel p-6 shadow-soft">
        <p className="text-xs uppercase tracking-[0.3em] text-muted">Setup Wizard</p>
        <h3 className="section-title mt-2 text-xl font-semibold">{current.title}</h3>
        <p className="mt-3 text-sm text-muted">{current.body}</p>
        <div className="mt-6 flex items-center justify-between text-xs text-muted">
          <span>
            Step {step + 1} of {steps.length}
          </span>
          <div className="flex gap-2">
            <button
              className="rounded-full border border-border px-4 py-2"
              onClick={() => {
                window.localStorage.setItem("wizardDismissed", "1");
                setOpen(false);
              }}
            >
              Skip for now
            </button>
            {step < steps.length - 1 ? (
              <button
                className="rounded-full bg-teal px-4 py-2 text-xs font-semibold text-base"
                onClick={() => setStep(step + 1)}
              >
                Continue
              </button>
            ) : (
              <button
                className="rounded-full bg-purple px-4 py-2 text-xs font-semibold text-white"
                onClick={() => {
                  window.localStorage.setItem("wizardDismissed", "1");
                  setOpen(false);
                }}
              >
                Finish
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

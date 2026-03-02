import { useMemo, useState } from "react";
import { SectionHeader } from "../components/SectionHeader";
import { useReasoning, useTuning } from "../hooks/useApiData";
import { postTuning } from "../api/tuning";
import { RuleTuning } from "../types";

export function Tuning() {
  const reasoning = useReasoning();
  const tuning = useTuning();
  const tuningMap = useMemo(() => {
    const map = new Map<string, RuleTuning>();
    tuning.forEach((t) => map.set(t.rule_id, t));
    return map;
  }, [tuning]);

  const [local, setLocal] = useState<Record<string, RuleTuning>>({});
  const [status, setStatus] = useState<Record<string, string>>({});

  const resolve = (ruleId: string): RuleTuning => {
    if (local[ruleId]) return local[ruleId];
    return (
      tuningMap.get(ruleId) || {
        rule_id: ruleId,
        enabled: true,
        min_confidence: 0,
        require_approval: false
      }
    );
  };

  const updateLocal = (ruleId: string, patch: Partial<RuleTuning>) => {
    setLocal((prev) => ({
      ...prev,
      [ruleId]: {
        ...resolve(ruleId),
        ...patch,
        rule_id: ruleId
      }
    }));
  };

  return (
    <div className="space-y-6">
      <section className="card">
        <SectionHeader title="Tuning" subtitle="Pilot-safe rule controls (applies on next assessment run)" />
        <p className="mt-2 text-sm text-muted">
          Use this to disable noisy rules, set a minimum confidence, or require approval before escalation.
        </p>
      </section>

      <section className="grid gap-4">
        {reasoning.map((item) => {
          const t = resolve(item.id);
          return (
            <div key={item.id} className="rounded-2xl border border-border bg-panel p-5">
              <div className="flex flex-wrap items-center justify-between gap-4">
                <div>
                  <p className="text-xs uppercase tracking-[0.2em] text-muted">{item.id}</p>
                  <h3 className="section-title mt-2 text-lg font-semibold">{item.title}</h3>
                  <p className="mt-1 text-xs text-muted">{item.reason_code || item.summary}</p>
                </div>
                <div className="text-xs text-muted">{status[item.id] || ""}</div>
              </div>

              <div className="mt-4 grid gap-4 md:grid-cols-3">
                <label className="flex items-center gap-3 text-sm text-text">
                  <input
                    type="checkbox"
                    checked={t.enabled}
                    onChange={(e) => updateLocal(item.id, { enabled: e.target.checked })}
                  />
                  Enabled
                </label>

                <label className="flex items-center gap-3 text-sm text-text">
                  Min confidence
                  <input
                    type="number"
                    step="0.05"
                    min="0"
                    max="0.99"
                    value={t.min_confidence}
                    onChange={(e) => updateLocal(item.id, { min_confidence: Number(e.target.value || 0) })}
                    className="w-24 rounded-lg border border-border bg-panelElev px-2 py-1 text-sm"
                  />
                </label>

                <label className="flex items-center gap-3 text-sm text-text">
                  <input
                    type="checkbox"
                    checked={t.require_approval}
                    onChange={(e) => updateLocal(item.id, { require_approval: e.target.checked })}
                  />
                  Require approval
                </label>
              </div>

              <div className="mt-4">
                <button
                  onClick={async () => {
                    setStatus((prev) => ({ ...prev, [item.id]: "Saving..." }));
                    try {
                      await postTuning(t);
                      setStatus((prev) => ({ ...prev, [item.id]: "Saved" }));
                    } catch {
                      setStatus((prev) => ({ ...prev, [item.id]: "Error" }));
                    }
                  }}
                  className="rounded-full border border-border px-4 py-2 text-xs uppercase tracking-wide text-muted hover:text-text"
                >
                  Save tuning
                </button>
              </div>
            </div>
          );
        })}
      </section>
    </div>
  );
}

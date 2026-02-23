# Metrics Summary

Generated: 2026-02-09

## Synthetic Accuracy
Source: `data/scenarios_realistic.json`
- Total labels: 106
- Accuracy: 0.887
- Class metrics (Precision/Recall):
  - feasible 1.000 / 0.984
  - incomplete 0.850 / 0.680
  - impossible 0.625 / 0.833
- Report: `docs/regression_report.md`

## Public Dataset Consistency
Source: `data/scenarios_public.json`
- Report: `docs/public_dataset_report.md`

## Pilot Dataset Impact
Source: `docs/pilot_metrics_report.md` (generated from `data/bench/report.json` + `data/incident_history.json`)
- Candidate alerts: 33
- Escalated alerts: 28
- Triaged alerts: 5
- Suppressed alerts: 0
- Queue reduction: 15.15%
- Escalated precision proxy (history-matched): 75.00%
- Suppressed-but-later-true rate: 0.00%
- Note: 24 escalated alerts are currently unmatched in history outcomes and require broader pilot labeling.

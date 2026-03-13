# attack_data Windows T1047 Validation

Dataset:
- `/Users/shak1532/Downloads/Aegis-R/data/scenarios_attack_data_windows_t1047.json`

Scope:
- Real Windows Security and Sysmon records extracted from `splunk/attack_data` T1047
- This pack is intentionally narrow. It scores only the rules directly supported by the current evidence.

Result:
- Accuracy: `100.00%`
- Total labeled checks: `3`
- Mismatches: `0`

Labels scored:
- `TA0002.WMI_EXEC` -> `incomplete`
- `TA0002.LOLBIN_CHAIN` -> `incomplete`
- `TA0006.PASS_THE_TICKET` -> `incomplete`

Interpretation:
- Aman now extracts meaningful Windows auth/control evidence from a real `attack_data` WMI slice.
- The engine still behaves conservatively because the slice lacks foothold, persistence, and ticket-reuse proof.
- This is the correct current behavior for an audit/governance-oriented validator.

Critical caveat:
- This is not a broad Windows score.
- The slice validates WMI-related normalization and reasoning only; it does not prove general endpoint maturity.
- The next high-value work remains stronger Windows auth chains, process-tree depth, and blocker/prevention semantics.

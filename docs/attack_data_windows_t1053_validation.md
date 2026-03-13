# attack_data Windows T1053 Validation

Dataset:
- `/Users/shak1532/Downloads/Aegis-R/data/scenarios_attack_data_windows_t1053.json`

Scope:
- Real Windows Security and Sysmon records extracted from `splunk/attack_data` T1053.005
- This pack is intentionally narrow. It scores only the rules directly supported by the current evidence.

Result:
- Accuracy: `100.00%`
- Total labeled checks: `4`
- Mismatches: `0`

Labels scored:
- `TA0002.SCHED_TASK_EXEC` -> `incomplete`
- `TA0003.PERSIST` -> `incomplete`
- `TA0006.CREDDUMP` -> `incomplete`
- `TA0006.PASS_THE_TICKET` -> `incomplete`

Interpretation:
- Aman now extracts meaningful Windows auth/control evidence from the real `attack_data` slice.
- The engine still behaves conservatively because the slice lacks explicit foothold, privilege-escalation, and ticket-reuse proof.
- This is the correct current behavior for an audit/governance-oriented validator.

Critical caveat:
- This is not a broad Windows score.
- The current slice still leaves several Windows records normalized as generic events or as context that does not yet drive stronger rules.
- The next high-value work remains broader Windows auth semantics and richer persistence/log-tamper mappings.

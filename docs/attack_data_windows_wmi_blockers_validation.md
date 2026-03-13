# attack_data Windows WMI Blocker Validation

Dataset:
- `/Users/shak1532/Downloads/Aegis-R/data/scenarios_attack_data_windows_wmi_blockers.json`

Scope:
- Real Windows WMI execution slice from `splunk/attack_data` T1047
- Real Windows blocker records from `splunk/attack_data` blocker-oriented records
- Two cases are scored:
  - blocker telemetry out of scope should leave the path `incomplete`
  - scope-aligned blocker telemetry should flip the WMI path to `impossible`

Result:
- Accuracy: `100.00%`
- Total labeled checks: `2`
- Mismatches: `0`

Labels scored:
- `TA0002.WMI_EXEC` -> `incomplete` when blocker telemetry is out of scope
- `TA0002.WMI_EXEC` -> `impossible` when blocker telemetry is scope-aligned

Interpretation:
- Aman now has a second Windows blocker/impossible validation case beyond admin-protocol lateral movement.
- Adding explicit contradictions and host context to `TA0002.WMI_EXEC` was necessary; without them, the engine could not distinguish denial noise from scope-aligned invalidation.

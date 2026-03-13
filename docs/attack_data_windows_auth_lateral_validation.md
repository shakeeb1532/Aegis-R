# attack_data Windows Auth/Lateral Validation

Dataset:
- `/Users/shak1532/Downloads/Aegis-R/data/scenarios_attack_data_windows_auth_lateral.json`

Scope:
- Real Windows `splunk/attack_data` auth and admin-protocol movement slice derived from the T1027 records
- Includes the environment-aware feasible case plus the paired blocker cases from the admin-protocol blocker pack

Result:
- Accuracy: `100.00%`
- Total labeled checks: `6`
- Mismatches: `0`

Labels scored:
- `TA0005.OBFUSCATED_FILES` -> `incomplete`
- `TA0006.CREDDUMP` -> `incomplete`
- `TA0006.PASS_THE_HASH` -> `incomplete`
- `TA0008.ADMIN_PROTOCOL_LATERAL` -> `feasible` in the base env-aware path
- `TA0008.ADMIN_PROTOCOL_LATERAL` -> `feasible` when blocker telemetry is out of scope
- `TA0008.ADMIN_PROTOCOL_LATERAL` -> `impossible` when blocker telemetry is scope-aligned

Interpretation:
- Aman now has a credible Windows auth-to-admin-protocol external slice that shows both positive movement and blocker-aware contradiction behavior.
- This is stronger than the earlier narrow T1027 slice because it demonstrates that the same rule can stay feasible or flip to impossible based on scoped blocker evidence rather than generic denial noise.

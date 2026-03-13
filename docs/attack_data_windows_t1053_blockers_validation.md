# attack_data Windows T1053 Blocker Validation

Dataset:
- `/Users/shak1532/Downloads/Aegis-R/data/scenarios_attack_data_windows_t1053_blockers.json`

Scope:
- Real blocker-oriented Windows Security records extracted from `splunk/attack_data` T1053
- Focuses on prevention/blocker normalization rather than full attack confirmation

Result:
- Accuracy: `100.00%`
- Total labeled checks: `3`
- Mismatches: `0`

Labels scored:
- `TA0003.PERSIST_EXTENDED` -> `incomplete`
- `TA0008.ADMIN_PROTOCOL_LATERAL` -> `incomplete`
- `TA0008.LATERAL` -> `incomplete`

Interpretation:
- Aman now normalizes real Windows blocker records into `signin_failed_auth`, `network_logon_failure`, and `admin_protocol_denied`.
- The engine remains conservative because blocker-only evidence without matching positive lateral-movement proof is not enough to produce a stronger blocked or conflicted verdict under the current rule model.
- This is useful external validation of normalization quality, but it also shows that richer real Windows admin-protocol evidence is still needed to strengthen blocker-side reasoning.

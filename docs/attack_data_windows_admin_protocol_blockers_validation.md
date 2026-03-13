# attack_data Windows Admin-Protocol Blocker Validation

Dataset:
- `/Users/shak1532/Downloads/Aegis-R/data/scenarios_attack_data_windows_admin_protocol_blockers.json`

Scope:
- Real Windows `splunk/attack_data` admin-protocol movement slice from the T1027 pack
- Real Windows blocker records from `splunk/attack_data` T1053 blocker-oriented records
- Two cases are scored:
  - out-of-scope blocker telemetry should not invalidate a feasible admin-protocol movement path
  - scope-aligned blocker telemetry should conflict the same path and drive an impossible result

Result:
- Accuracy: `100.00%`
- Total labeled checks: `2`
- Mismatches: `0`

Labels scored:
- `TA0008.ADMIN_PROTOCOL_LATERAL` -> `feasible` when blocker telemetry is out of scope
- `TA0008.ADMIN_PROTOCOL_LATERAL` -> `impossible` when blocker telemetry is scope-aligned

Interpretation:
- Aman now distinguishes between generic Windows denial noise and blocker evidence that actually correlates to the same admin-protocol movement context.
- This validates the scoped contradiction path for a real Windows attack-data-derived lateral movement slice instead of a synthetic-only test.
- Adding explicit contradictions to `TA0008.ADMIN_PROTOCOL_LATERAL` was necessary; without them, the engine had no formal way to treat admin-protocol denials as invalidating evidence for that rule.

Critical caveat:
- This is still a narrow Windows lateral slice, not broad endpoint readiness.
- The scope-aligned blocker case is built from real blocker records but aligned to the same host/source scope for evaluative purposes.
- More Windows auth/lateral slices are still needed before making broad blocker-side claims.

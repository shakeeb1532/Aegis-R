# attack_data Windows T1027 Validation

Dataset:
- `/Users/shak1532/Downloads/Aegis-R/data/scenarios_attack_data_windows_t1027.json`

Scope:
- Real Windows Security and Sysmon records extracted from `splunk/attack_data` T1027
- This pack is intentionally narrow. It scores only the rules directly supported by the current evidence.

Result:
- Accuracy: `100.00%`
- Total labeled checks: `4`
- Mismatches: `0`

Labels scored:
- `TA0005.OBFUSCATED_FILES` -> `incomplete`
- `TA0006.CREDDUMP` -> `incomplete`
- `TA0006.PASS_THE_HASH` -> `incomplete`
- `TA0008.ADMIN_PROTOCOL_LATERAL` -> `feasible`

Interpretation:
- Aman now extracts encoded PowerShell execution, explicit credential use, Kerberos activity, and LSASS access from a real `attack_data` obfuscation slice.
- The engine still behaves conservatively on the credential and obfuscation paths because the slice lacks initial access, privilege escalation, and explicit pass-the-hash replay proof.
- With explicit host environment context present, the same slice now supports `TA0008.ADMIN_PROTOCOL_LATERAL` as a feasible Windows admin-protocol movement path.
- Tightening `TA0006.PASS_THE_HASH` to require explicit replay evidence removed a circular feasibility path where `lsass_access` was satisfying both the evidence and the derived precondition.

Critical caveat:
- This is not broad Windows endpoint coverage.
- The slice validates encoded-command and credential-access handling only; it does not prove mature Windows auth or prevention semantics.
- The next high-value work remains broader blocker/prevention coverage and richer Windows auth/lateral chains.

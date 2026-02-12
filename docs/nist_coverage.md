# NIST CSF Coverage

Aman maps rules to NIST CSF categories for reporting and audit context.

## CLI
```bash
go run ./cmd/aman system nist -rules data/rules.json
go run ./cmd/aman system nist -rules data/rules.json --json
go run ./cmd/aman system nist -rules data/rules.json -out docs/nist_coverage.json
```

## Notes
- By default, most detection rules map to **Detect**.
- Impact and exfiltration rules include **Respond** (and **Recover** for impact).
- Defense evasion and logging tamper rules include **Protect** + **Detect**.

# MITRE Coverage Reporting

Aegis-R can summarize ATT&CK coverage directly from the rule catalog.

## CLI
```bash
go run ./cmd/aegisr system coverage -rules data/rules.json
go run ./cmd/aegisr system coverage -rules data/rules.json --json
go run ./cmd/aegisr system coverage -rules data/rules.json -env data/env.json
go run ./cmd/aegisr system coverage -rules data/rules.json -env data/env.json -out docs/coverage_env.md
```

## Output
The report shows:
- total rules
- rules with MITRE metadata
- tactics covered and technique counts

Use this report to track coverage expansion and to document coverage in audits.

## Platform Alignment (v16+)

MITRE ATT&CK v16 introduced **Identity Provider** and **Office Suite** platforms. Aegis-R tags related rules as follows:

- `identity_provider`: device code phishing, OAuth consent phishing, device join, MFA bypass, identity anomalies.
- `office_suite`: mailbox persistence and OAuth consent flows.
- `cloud`: cloud lateral movement rules.

These tags are stored in the `mitre.links` field and can be grouped in reports.

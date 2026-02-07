# MITRE Coverage Reporting

Aegis-R can summarize ATT&CK coverage directly from the rule catalog.

## CLI
```bash
go run ./cmd/aegisr system coverage -rules data/rules.json
go run ./cmd/aegisr system coverage -rules data/rules.json --json
```

## Output
The report shows:
- total rules
- rules with MITRE metadata
- tactics covered and technique counts

Use this report to track coverage expansion and to document coverage in audits.

# Cyber Kill Chain Coverage

Aman maps rules to Kill Chain phases for reporting and audit context.

## CLI
```bash
go run ./cmd/aman system killchain -rules data/rules.json
go run ./cmd/aman system killchain -rules data/rules.json --json
go run ./cmd/aman system killchain -rules data/rules.json -out docs/kill_chain_coverage.json
```

## Notes
- Initial Access rules map to **Delivery**.
- Execution/Privilege/Lateral rules map to **Exploitation**.
- Persistence rules map to **Installation**.
- C2 rules map to **C2**.
- Exfiltration/Impact rules map to **Actions**.

# Test Results

Generated: 2026-02-08

## Unit + Integration

Command:
```bash
go test ./...
```

Result:
```
?   	aegisr/cmd/aegisr	[no test files]
ok   	aegisr/internal/approval	(cached)
ok   	aegisr/internal/audit	(cached)
ok   	aegisr/internal/core	(cached)
ok   	aegisr/internal/env	(cached)
ok   	aegisr/internal/eval	(cached)
ok   	aegisr/internal/governance	(cached)
ok   	aegisr/internal/integration	(cached)
ok   	aegisr/internal/inventory	(cached)
ok   	aegisr/internal/logic	(cached)
?   	aegisr/internal/model	[no test files]
?   	aegisr/internal/ops	[no test files]
ok   	aegisr/internal/progression	(cached)
?   	aegisr/internal/report	[no test files]
?   	aegisr/internal/sim	[no test files]
?   	aegisr/internal/state	[no test files]
?   	aegisr/internal/testutil	[no test files]
ok   	aegisr/internal/ui	(cached)
ok   	aegisr/internal/validate	(cached)
?   	aegisr/internal/zerotrust	[no test files]
?   	aegisr/scripts	[no test files]
```

## Regression Evaluation

Command:
```bash
go run ./cmd/aegisr evaluate -scenarios data/scenarios_realistic.json -rules data/rules.json -format md -out docs/regression_report.md
```

Output:
- `docs/regression_report.md`

## Notes
- For CI/verification steps, see `docs/ci_checklist.md`.
- For confidence band interpretation, see `docs/confidence_bands.md`.

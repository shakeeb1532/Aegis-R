# Test Results

Generated: 2026-02-09

## Unit + Integration

Command:
```bash
go test ./...
```

Result:
```
?   	aman/cmd/aman	[no test files]
ok   	aman/internal/approval	(cached)
ok   	aman/internal/audit	(cached)
ok   	aman/internal/core	(cached)
ok   	aman/internal/env	(cached)
ok   	aman/internal/eval	(cached)
ok   	aman/internal/governance	(cached)
ok   	aman/internal/integration	(cached)
ok   	aman/internal/inventory	(cached)
ok   	aman/internal/logic	(cached)
?   	aman/internal/model	[no test files]
?   	aman/internal/ops	[no test files]
ok   	aman/internal/progression	(cached)
?   	aman/internal/report	[no test files]
?   	aman/internal/sim	[no test files]
?   	aman/internal/state	[no test files]
?   	aman/internal/testutil	[no test files]
ok   	aman/internal/ui	(cached)
ok   	aman/internal/validate	(cached)
?   	aman/internal/zerotrust	[no test files]
?   	aman/scripts	[no test files]
```

## Regression Evaluation

Command:
```bash
go run ./cmd/aman evaluate -scenarios data/scenarios_realistic.json -rules data/rules.json -format md -out docs/regression_report.md
```

Output:
- `docs/regression_report.md`

## Public Dataset Consistency

Command:
```bash
go run ./cmd/aman evaluate -scenarios data/scenarios_public.json -rules data/rules.json -format md -out docs/public_dataset_report.md
```

Output:
- `docs/public_dataset_report.md`

## Performance Snapshot (Apple M1)

Assess:
- 1k: 1.67 ms/op, 1.50 MB/op, 4,696 allocs/op
- 10k: 13.1 ms/op, 12.4 MB/op, 37,233 allocs/op
- 100k: 141.8 ms/op, 189 MB/op, 361,568 allocs/op

Reason:
- 1k: 0.124 ms/op, 0.55 MB/op, 623 allocs/op
- 10k: 2.08 ms/op, 6.0 MB/op, 688 allocs/op
- 100k: 15.3 ms/op, 74 MB/op, 814 allocs/op

## Audit Compression Benchmarks (Apple M1)

Append throughput:
- JSONL: 24.4 µs/op, 792 B/op, 11 allocs/op
- LZ4: 27.2 µs/op, 1145 B/op, 12 allocs/op

Compression ratio (sample artifact):
- Single artifact JSON: 293 B → 256 B (12.6% smaller)
- End-to-end audit log (demo events): 7.1 KB → 1.1 KB (~84.5% smaller)

Report output:
- JSON report: 54 KB → 9.2 KB (~83% smaller) when using `-out report.json.lz4`

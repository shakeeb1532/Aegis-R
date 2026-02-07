# CI Checklist

- `go test ./...`
- `go test -race ./...`
- `golangci-lint run`
- `go run ./cmd/aegisr generate-scenarios -out /tmp/scenarios.json -rules data/rules.json`
- `go run ./cmd/aegisr evaluate -scenarios /tmp/scenarios.json -rules data/rules.json -format cli`
- `go run ./cmd/aegisr evaluate -scenarios data/scenarios_realistic.json -rules data/rules.json -format md -out /tmp/regression_report.md`
- `docker build -t aegisr:ci .`
- `govulncheck ./...`

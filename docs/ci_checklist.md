# CI Checklist

- `go test ./...`
- `go test -race ./...`
- `golangci-lint run`
- `go run ./cmd/aman generate-scenarios -out /tmp/scenarios.json -rules data/rules.json`
- `go run ./cmd/aman evaluate -scenarios /tmp/scenarios.json -rules data/rules.json -format cli`
- `go run ./cmd/aman evaluate -scenarios data/scenarios_realistic.json -rules data/rules.json -format md -out /tmp/regression_report.md`
- `docker build -t aman:ci .`
- `govulncheck ./...`

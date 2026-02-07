# Release Checklist

1. Ensure working tree is clean.
2. Run local verification:
   - `go test ./...`
   - `go test -race ./...`
   - `golangci-lint run`
   - `go run ./cmd/aegisr evaluate -scenarios data/scenarios_realistic.json -rules data/rules.json -format md -out docs/regression_report.md`
3. Update `CHANGELOG.md` with release notes.
4. Tag the release (example):
   - `git tag v0.1.0`
   - `git push origin v0.1.0`
5. Verify GitHub Actions release workflow:
   - GoReleaser publishes binaries
   - GHCR image `ghcr.io/shakeeb1532/aegis-r:<tag>`

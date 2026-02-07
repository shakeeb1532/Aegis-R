# Confidence Band Reporting

Generate a simple confidence band report from a reasoning report.

```bash
go run ./cmd/aegisr system confidence -report report.json
go run ./cmd/aegisr system confidence -report report.json -out docs/confidence_report.md
```

Bands:
- High: >= 0.80
- Medium: 0.60–0.79
- Low: < 0.60

This report is heuristic and intended for coarse calibration checks.

# BOTS v1 Windows Real Export Validation

This document records Aman running against a small real export slice from `splunk/botsv1`.

## Source fixtures

- Windows Security export: `/Users/shak1532/Downloads/Aegis-R/data/fixtures/botsv1_windows_security.json`
- Sysmon export: `/Users/shak1532/Downloads/Aegis-R/data/fixtures/botsv1_sysmon.json`

These fixtures were built from real `result` objects streamed from:

- `botsv1.WinEventLog-Security.json.gz`
- `botsv1.XmlWinEventLog-Microsoft-Windows-Sysmon-Operational.json.gz`

The raw samples include:

- Windows Security `4624` successful network logon
- Windows Security `4688` process creation
- Sysmon `1` process creation
- Sysmon `3` network connection

## Commands used

```bash
go run ./cmd/aman ingest file \
  -in /Users/shak1532/Downloads/Aegis-R/data/fixtures/botsv1_windows_security.json \
  -schema windows_security_json \
  -out /tmp/botsv1_windows_events.json

go run ./cmd/aman ingest file \
  -in /Users/shak1532/Downloads/Aegis-R/data/fixtures/botsv1_sysmon.json \
  -schema sysmon_json \
  -out /tmp/botsv1_sysmon_events.json

go run ./cmd/aman assess \
  -in /tmp/botsv1_windows_combined_events.json \
  -env /Users/shak1532/Downloads/Aegis-R/data/env.json \
  -state /tmp/botsv1_windows_state.json \
  -audit /tmp/botsv1_windows_audit.log \
  -rules /Users/shak1532/Downloads/Aegis-R/data/rules.json \
  > /tmp/botsv1_windows_report.json
```

## Normalization result

The real BOTS v1 export normalized into 6 Aman events:

- `signin_success`
- `valid_account_login`
- `network_logon`
- `process_creation` (Windows Security 4688)
- `process_creation` (Sysmon 1)
- `network_connection` (Sysmon 3)

## Assessment summary

- Normalized event count: `6`
- Reasoning results evaluated: `232`
- Findings produced: `230`
- Threads created: `0`
- Tickets created: `0`

Structured output:

- `/Users/shak1532/Downloads/Aegis-R/docs/botsv1_windows_real_report.json`

## What this says about Aman

### Good

- Aman can now ingest real BOTS v1 Windows Security exports, not only synthetic fixtures.
- The new `windows_security_json` adapter correctly understands:
  - real `4624` network logons
  - real `4688` process creation
- The `sysmon_json` adapter correctly handles real BOTS v1 Sysmon exports.
- Time parsing for Splunk-style `_time` fields now works.

### Not good enough yet

- This slice is still too small to claim BOTS readiness.
- The current rule catalog overreacts to generic `process_creation` support, which produces too many low-value `evidence_gap` findings.
- Windows auth-to-identity reasoning is still shallow.
- Process-tree-aware contradiction handling is improved, but still not deep enough for serious endpoint/lateral reasoning claims.

## Main technical issue exposed

The biggest issue in this run is not ingestion failure. It is semantic breadth:

- real BOTS v1 Windows events map successfully
- but a small number of generic Windows process events still light up too many rules indirectly

That means the next serious Windows/BOTS hardening step should be:

1. reduce over-broad dependence on `process_creation`
2. expand Windows auth and lateral-movement semantics
3. add more real BOTS v1 export slices before scoring

## Conclusion

This run proves that Aman can now process a real BOTS v1 Windows export slice through its native ingest and reasoning path. It does **not** prove that Aman is fully BOTS-ready. The adapter gap is now largely removed; the remaining work is reasoning specificity and broader Windows coverage.

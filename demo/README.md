# Aegis-R Pilot Demo Pack

This demo pack is designed to show Aegis-R running on real public telemetry in a read-only mode.

## Contents
- CloudTrail demo (Splunk Attack Data)
- Windows Event Log demo (Security Datasets)
- Pre-generated outputs (assessment + audit + SIEM export)

## Quick Run
```bash
./demo/run_demo.sh
```

## Outputs
CloudTrail demo:
- data/fixtures/splunk_attack_data/assessment_clean.json
- data/fixtures/splunk_attack_data/audit.log
- data/fixtures/splunk_attack_data/siem.json

Windows demo:
- data/fixtures/securitydatasets/assessment_clean.json
- data/fixtures/securitydatasets/audit.log
- data/fixtures/securitydatasets/siem.json

## What to Show
- Evidence-backed findings in the reasoning output
- Evidence gaps and reachability gating
- Audit chain and signed artifacts
- Decision labels and ticket formation

## Notes
- A zero-trust baseline is required. The script will create it if missing.
- Admin-gated rules remain disabled unless you provide an admin approval file.

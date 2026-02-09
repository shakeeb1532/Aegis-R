# Pilot Demo Pack (Aegis-R)

Generated: 2026-02-08

This pack is designed to demonstrate Aegis-R using real public telemetry in a read-only workflow.

## What’s Included
- CloudTrail demo using Splunk Attack Data
- Windows event log demo using Security Datasets
- Assessment outputs (reasoning, audit, SIEM export)

## Quick Start
```bash
./demo/run_demo.sh
```

## CloudTrail Demo
Input:
- `data/fixtures/splunk_attack_data/combined_cloudtrail.json`

Outputs:
- `data/fixtures/splunk_attack_data/assessment_clean.json`
- `data/fixtures/splunk_attack_data/audit.log`
- `data/fixtures/splunk_attack_data/siem.json`

Expected evidence-backed rules in this dataset:
- `TA0005.IMPAIR_DEFENSES`
- `TA0005.LOG_TAMPER`
- `TA0006.BRUTE_FORCE`
- `TA0006.VALID_ACCOUNTS`
- `TA0010.BULK_EXFIL`
- `TA0006.INSIDER_EXFIL`

## Windows Demo
Input:
- `data/fixtures/securitydatasets/cmd_mshta_vbscript_execute_psh_2020-10-2202580804.json`

Outputs:
- `data/fixtures/securitydatasets/assessment_clean.json`
- `data/fixtures/securitydatasets/audit.log`
- `data/fixtures/securitydatasets/siem.json`

Expected evidence-backed rules in this dataset:
- `TA0002.LOLBIN_CHAIN`
- `TA0005.IMPAIR_DEFENSES`
- `TA0005.LOG_TAMPER`
- `TA0006.CREDDUMP`

## What to Show in a Pilot Demo
- Evidence-backed reasoning (rule results with supporting events)
- Evidence gaps and reachability gating
- Decision labels and ticket creation
- Audit chain verification

## Notes
- A zero-trust baseline is required. The script creates one if missing.
- Admin-gated rules remain disabled unless you provide an admin approval file.

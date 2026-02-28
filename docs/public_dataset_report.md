# Regression Report

Generated: 2026-02-27T23:54:27Z

- Total labels: 31
- Accuracy: 0.806

## Class Metrics

| Class | Precision | Recall |
| --- | --- | --- |
| feasible | 0.900 | 0.750 |
| incomplete | 0.750 | 0.938 |
| impossible | 1.000 | 0.333 |

## Mismatches (first 20)

| Scenario | Rule | Expected | Actual |
| --- | --- | --- | --- |
| public-cloudtrail-exfil | TA0006.INSIDER_EXFIL | feasible | incomplete |
| public-windows-lolbin | TA0002.LOLBIN_CHAIN | impossible | incomplete |
| public-cloudtrail-log-tamper | TA0005.LOG_TAMPER | impossible | incomplete |
| public-sentinel-lateral | TA0008.LATERAL | feasible | incomplete |
| public-mfa-bypass | TA0004.MFA_BYPASS | incomplete | feasible |
| public-log-tamper-feasible | TA0005.LOG_TAMPER | feasible | incomplete |

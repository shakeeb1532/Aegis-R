# Regression Report

Generated: 2026-03-10T00:27:46Z

- Total labels: 31
- Accuracy: 0.871

## Class Metrics

| Class | Precision | Recall |
| --- | --- | --- |
| feasible | 1.000 | 0.833 |
| incomplete | 0.800 | 1.000 |
| impossible | 1.000 | 0.333 |

## Mismatches (first 20)

| Scenario | Rule | Expected | Actual |
| --- | --- | --- | --- |
| public-cloudtrail-exfil | TA0006.INSIDER_EXFIL | feasible | incomplete |
| public-windows-lolbin | TA0002.LOLBIN_CHAIN | impossible | incomplete |
| public-cloudtrail-log-tamper | TA0005.LOG_TAMPER | impossible | incomplete |
| public-log-tamper-feasible | TA0005.LOG_TAMPER | feasible | incomplete |

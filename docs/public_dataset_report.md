# Regression Report

Generated: 2026-02-09T02:07:00Z

- Total labels: 7
- Accuracy: 0.714

## Class Metrics

| Class | Precision | Recall |
| --- | --- | --- |
| feasible | 1.000 | 1.000 |
| incomplete | 1.000 | 0.600 |
| impossible | 0.333 | 1.000 |

## Mismatches (first 20)

| Scenario | Rule | Expected | Actual |
| --- | --- | --- | --- |
| public-cloudtrail-exfil | TA0010.BULK_EXFIL | incomplete | impossible |
| public-windows-lolbin | TA0005.LOG_TAMPER | incomplete | impossible |

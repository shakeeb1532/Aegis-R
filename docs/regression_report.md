# Regression Report

Generated: 2026-02-09T04:23:11Z

- Total labels: 127
- Accuracy: 0.953

## Class Metrics

| Class | Precision | Recall |
| --- | --- | --- |
| feasible | 0.970 | 1.000 |
| incomplete | 1.000 | 0.884 |
| impossible | 0.826 | 0.950 |

## Mismatches (first 20)

| Scenario | Rule | Expected | Actual |
| --- | --- | --- | --- |
| hard-contradiction-privesc-mfa-enforced | TA0004.PRIVESCA | impossible | feasible |
| hard-ambig-identity-feasible | TA0006.IDENTITY_ANOMALY | incomplete | feasible |
| hard-ambig-creddump-precond | TA0006.CREDDUMP | incomplete | impossible |
| hard-ambig-exfil-precond | TA0010.EXFIL | incomplete | impossible |
| hard-ambig-lateral-precond | TA0008.LATERAL | incomplete | impossible |
| hard-ambig-persist-precond | TA0003.PERSIST | incomplete | impossible |

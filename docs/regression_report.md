# Regression Report

Generated: 2026-02-09T01:53:29Z

- Total labels: 104
- Accuracy: 0.894

## Class Metrics

| Class | Precision | Recall |
| --- | --- | --- |
| feasible | 1.000 | 1.000 |
| incomplete | 0.850 | 0.680 |
| impossible | 0.619 | 0.812 |

## Mismatches (first 20)

| Scenario | Rule | Expected | Actual |
| --- | --- | --- | --- |
| realistic-2 | TA0002.LOLBIN_CHAIN | incomplete | impossible |
| realistic-11 | TA0005.LOG_TAMPER | incomplete | impossible |
| realistic-16 | TA0011.C2 | incomplete | impossible |
| realistic-17 | TA0010.EXFIL | incomplete | impossible |
| realistic-18 | TA0006.CREDDUMP | incomplete | impossible |
| realistic-19 | TA0008.ADMIN_PROTOCOL_LATERAL | incomplete | impossible |
| realistic-20 | TA0003.MAILBOX_PERSIST | incomplete | impossible |
| adversarial-TA0002.LOLBIN_CHAIN | TA0002.LOLBIN_CHAIN | incomplete | impossible |
| realistic-impossible-TA0006.IDENTITY_ANOMALY | TA0006.IDENTITY_ANOMALY | impossible | incomplete |
| realistic-impossible-TA0004.PRIVESCA | TA0004.PRIVESCA | impossible | incomplete |
| realistic-impossible-TA0006.VALID_ACCOUNTS | TA0006.VALID_ACCOUNTS | impossible | incomplete |

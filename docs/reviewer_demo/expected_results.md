# Expected Results

This is the current baseline for the reviewer demo.

Generated from:

```bash
bash /Users/shak1532/Downloads/Aegis-R/docs/reviewer_demo/run_demo.sh /tmp/aman-reviewer-demo
```

## Expected Signals

- Assessment completes successfully.
- Audit package completes successfully.
- Bundle verification passes.
- The assessment surfaces a compact set of feasible attack paths rather than only raw alerts.

## Current Baseline

- Feasible findings: `10`
- Example feasible rules:
  - `TA0001.DEVICE_CODE_PHISH`
  - `TA0001.DEVICE_JOIN_PHISH`
  - `TA0001.OAUTH_CONSENT_PHISH`
  - `TA0001.PHISHING`
  - `TA0001.STOLEN_CREDS`
  - `TA0002.LOLBIN_CHAIN`
  - `TA0004.MFA_BYPASS`
  - `TA0006.IDENTITY_ANOMALY`
  - `TA0006.VALID_ACCOUNTS`

## Current Next-Move Examples

- `Likely lateral movement to critical host host-3`
- `Likely lateral movement to critical host host-4`
- `Possible lateral movement to host host-1`
- `Privilege escalation target: identity svc-admin`

## Current Bundle Verification Baseline

```text
Bundle files verified: 12
Digest: VALID
Signature: NOT PRESENT
Evidence bundle verification passed
```

If the exact set of feasible findings changes after rule work, treat that as a normal rule-catalog change. The failure condition is not “counts changed.” The failure condition is:

- the run does not complete
- the bundle does not verify
- the output stops being understandable

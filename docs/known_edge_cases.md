# Known Edge Cases (Documented)

These are intentionally kept as known mismatches to preserve conservative logic and avoid overfitting.

## Public Dataset

1) `public-ecs-lolbin`  
- Expected: `incomplete`  
- Actual: `impossible`  
- Rationale: engine treats missing preconditions as impossible when evidence is partial and no supporting context exists.

2) `public-mfa-bypass`  
- Expected: `incomplete`  
- Actual: `feasible`  
- Rationale: MFA disabled + token anomaly is treated as sufficient evidence of bypass.

3) `public-log-tamper-feasible`  
- Expected: `feasible`  
- Actual: `impossible`  
- Rationale: rule expects both disable_logging + policy_bypass; if either is missing or context is absent, it is conservative.

## Synthetic (Realistic Suite)

1) `hard-contradiction-privesc-mfa-enforced`  
- Expected: `impossible`  
- Actual: `feasible`  
- Rationale: explicit “MFA enforced block” contradiction not modeled yet.

2) `hard-ambig-identity-feasible`  
- Expected: `incomplete`  
- Actual: `feasible`  
- Rationale: identity anomaly rule fires on strong evidence even when analyst expects incomplete.

3) `hard-ambig-creddump-precond`  
4) `hard-ambig-exfil-precond`  
5) `hard-ambig-lateral-precond`  
6) `hard-ambig-persist-precond`  
- Expected: `incomplete`  
- Actual: `impossible`  
- Rationale: precondition strictness is deliberately conservative in ambiguous cases.


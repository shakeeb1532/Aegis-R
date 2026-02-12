# Sample Outputs

## MITRE Coverage (env-scoped)
```
MITRE coverage
Rules total: 30
Applicable rules: 30
Rules with MITRE: 30
Rules missing MITRE: 0
Tactics:
- TA0001: 2 rules, 1 techniques
  - T1566 (T1566.001, T1566.002): 2 rules
- TA0002: 1 rules, 1 techniques
  - T1059: 1 rules
- TA0003: 3 rules, 3 techniques
  - T1060: 1 rules
  - T1098: 1 rules
  - T1543: 1 rules
- TA0004: 4 rules, 3 techniques
  - T1068: 1 rules
  - T1098: 2 rules
  - T1556: 1 rules
- TA0005: 4 rules, 3 techniques
  - T1090: 1 rules
  - T1556: 1 rules
  - T1562 (T1562.001): 2 rules
- TA0006: 5 rules, 4 techniques
  - T1003 (T1003.001): 1 rules
  - T1078: 2 rules
  - T1110: 1 rules
  - T1530: 1 rules
- TA0008: 3 rules, 2 techniques
  - T1021: 2 rules
  - T1078: 1 rules
- TA0010: 3 rules, 3 techniques
  - T1020: 1 rules
  - T1041: 1 rules
  - T1567 (T1567.002): 1 rules
- TA0011: 2 rules, 1 techniques
  - T1071 (T1071.004): 2 rules
- TA0040: 2 rules, 2 techniques
  - T1486: 1 rules
  - T1490: 1 rules
- TA0043: 1 rules, 1 techniques
  - T1195: 1 rules
```

## Reasoning Output (Batch A)
```
Gated rules disabled: TA0005.EVASION_C2, TA0040.IMPACT_ENCRYPT
Admin approval required at install time to enable these packs.
Aman Reasoning Report (2026-02-07T12:04:16Z)
Feasibility reasoning over evidence and preconditions.

Confidence model: heuristic
Confidence note: Rule-based heuristic confidence; not calibrated.

- [FEASIBLE] Identity Anomaly (Impossible Travel / New Device) (TA0006.IDENTITY_ANOMALY, 0.85)
  Identity anomalies indicate possible account compromise.
  Evidence IDs: id-1, id-2

- [FEASIBLE] Suspicious LOLBin Execution Chain (TA0002.LOLBIN_CHAIN, 0.85)
  LOLBin execution following initial access suggests hands-on-keyboard activity.
  Evidence IDs: ep-1, ep-2

- [FEASIBLE] MFA Disable or Bypass (TA0004.MFA_BYPASS, 0.85)
  MFA changes combined with token anomalies indicate bypass.
  Evidence IDs: id-3, id-4

- [NOT FEASIBLE] Modify Authentication Process (TA0005.AUTH_PROCESS_MOD, 0.55)
  Decision: 
  Reason code: evidence_gap
  Authentication controls were altered to bypass access checks. Missing evidence: auth_process_modify
  Gap: This attack would require auth_process_modify but no such evidence was observed.
  Evidence IDs: id-3
  Missing Evidence:
  - auth_process_modify: Authentication process modified

- [NOT FEASIBLE] Impair Defenses (TA0005.IMPAIR_DEFENSES, 0.55)
  Decision: 
  Reason code: evidence_gap
  Defensive controls weakened to evade detection. Missing evidence: disable_logging, cloud_firewall_change
  Gap: This attack would require disable_logging, cloud_firewall_change but no such evidence was observed.
  Missing Evidence:
  - disable_logging: Security logging disabled or altered
  - cloud_firewall_change: Cloud firewall or security group opened

- [NOT FEASIBLE] Command and Control (TA0011.C2, 0.55)
  Decision: 
  Reason code: evidence_gap
  C2 established after initial access. Missing evidence: beacon_outbound, dns_tunneling
  Gap: This attack would require beacon_outbound, dns_tunneling but no such evidence was observed.
  Missing Evidence:
  - beacon_outbound: Outbound beacon to known C2
  - dns_tunneling: DNS tunneling patterns

- [NOT FEASIBLE] Admin Protocol Lateral Movement (TA0008.ADMIN_PROTOCOL_LATERAL, 0.55)
  Decision: 
  Reason code: evidence_gap
  Lateral movement over admin protocols with valid credentials. Missing evidence: new_inbound_admin_protocol, network_logon
  Gap: This attack would require new_inbound_admin_protocol, network_logon but no such evidence was observed.
  Missing Evidence:
  - new_inbound_admin_protocol: New inbound admin protocol used
  - network_logon: Successful network logon

- [NOT FEASIBLE] Privilege Escalation (TA0004.PRIVESCA, 0.55)
  Decision: 
  Reason code: evidence_gap
  Evidence of elevating access beyond initial privileges. Missing evidence: token_manipulation, admin_group_change
  Gap: This attack would require token_manipulation, admin_group_change but no such evidence was observed.
  Missing Evidence:
  - token_manipulation: Token manipulation activity
  - admin_group_change: User added to admin group

- [NOT FEASIBLE] Lateral Movement (TA0008.LATERAL, 0.55)
  Decision: 
  Reason code: evidence_gap
  Requires valid credentials before remote execution. Missing evidence: remote_service_creation, network_logon
  Gap: This attack would require remote_service_creation, network_logon but no such evidence was observed.
  Missing Evidence:
  - remote_service_creation: Remote service created
  - network_logon: Successful network logon

- [NOT FEASIBLE] Bulk Data Exfiltration (TA0010.BULK_EXFIL, 0.55)
  Decision: 
  Reason code: evidence_gap
  Bulk data access followed by outbound transfer. Missing evidence: bulk_download, large_outbound_transfer
  Gap: This attack would require bulk_download, large_outbound_transfer but no such evidence was observed.
  Missing Evidence:
...
  - bulk_download: Bulk data access or download
  - large_outbound_transfer: Large outbound data transfer

- [NOT FEASIBLE] Extended Persistence Mechanisms (TA0003.PERSIST_EXTENDED, 0.55)
  Decision: 
  Reason code: evidence_gap
  Persistence via registry and services after initial access. Missing evidence: registry_run_key
  Gap: This attack would require registry_run_key but no such evidence was observed.
  Evidence IDs: ep-3
  Missing Evidence:
  - registry_run_key: Registry run key set

- [NOT FEASIBLE] Valid Accounts Abuse (TA0006.VALID_ACCOUNTS, 0.55)
  Decision: 
  Reason code: evidence_gap
  Compromised valid accounts enable access without malware. Missing evidence: valid_account_login
  Gap: This attack would require valid_account_login but no such evidence was observed.
  Evidence IDs: id-2
  Missing Evidence:
  - valid_account_login: Login using valid credentials in unusual context

- [NOT FEASIBLE] Brute Force / Credential Stuffing (TA0006.BRUTE_FORCE, 0.55)
  Decision: 
  Reason code: evidence_gap
  High-volume authentication failures followed by access attempts. Missing evidence: password_spray, credential_stuffing
  Gap: This attack would require password_spray, credential_stuffing but no such evidence was observed.
  Missing Evidence:
  - password_spray: Password spraying pattern detected
  - credential_stuffing: Credential stuffing pattern detected

- [NOT FEASIBLE] Account Manipulation (TA0004.ACCOUNT_MANIP, 0.55)
  Decision: 
  Reason code: evidence_gap
  Account changes used to persist or elevate access. Missing evidence: account_manipulation, admin_group_change
  Gap: This attack would require account_manipulation, admin_group_change but no such evidence was observed.
  Missing Evidence:
  - account_manipulation: Account permissions or credentials modified
  - admin_group_change: User added to privileged group

- [NOT FEASIBLE] Initial Access via Phishing (TA0001.PHISHING, 0.55)
  Decision: 
  Reason code: evidence_gap
  User interaction and macro execution leading to outbound beaconing. Missing evidence: beacon_outbound
  Gap: This attack would require beacon_outbound but no such evidence was observed.
  Evidence IDs: ia-1, ia-2
  Missing Evidence:
  - beacon_outbound: Outbound beacon to known C2

- [NOT FEASIBLE] Application Layer Protocol C2 (TA0011.APP_LAYER_C2, 0.55)
  Decision: 
  Reason code: evidence_gap
  C2 over common application protocols for stealth. Missing evidence: app_layer_c2, beacon_outbound
  Gap: This attack would require app_layer_c2, beacon_outbound but no such evidence was observed.
  Missing Evidence:
  - app_layer_c2: C2 over web/mail/DNS protocols
  - beacon_outbound: Outbound beaconing to known C2

- [NOT FEASIBLE] Persistence (TA0003.PERSIST, 0.55)
  Decision: 
  Reason code: evidence_gap
  Persistence established after initial access. Missing evidence: registry_run_key, scheduled_task
  Gap: This attack would require registry_run_key, scheduled_task but no such evidence was observed.
  Missing Evidence:
  - registry_run_key: Registry run key set
  - scheduled_task: Scheduled task created

- [NOT FEASIBLE] Disable or Modify Security Logging (TA0005.LOG_TAMPER, 0.55)
  Decision: 
  Reason code: evidence_gap
  Disabling logging to hide attacker activity. Missing evidence: disable_logging, policy_bypass
  Gap: This attack would require disable_logging, policy_bypass but no such evidence was observed.
  Missing Evidence:
  - disable_logging: Security logging disabled
  - policy_bypass: Control policy bypassed

- [NOT FEASIBLE] Phishing via Link and OAuth Consent (TA0001.PHISH_LINK, 0.55)
  Decision: 
  Reason code: evidence_gap
  Link phishing followed by OAuth consent indicates account compromise. Missing evidence: phish_link_click, oauth_consent
  Gap: This attack would require phish_link_click, oauth_consent but no such evidence was observed.
```

Notes:
- Output truncated for brevity. The full CLI output can be generated with:
  - Gated rules disabled: TA0005.EVASION_C2, TA0040.IMPACT_ENCRYPT
Admin approval required at install time to enable these packs.
Aman Reasoning Report (2026-02-07T12:04:16Z)
Feasibility reasoning over evidence and preconditions.

Confidence model: heuristic
Confidence note: Rule-based heuristic confidence; not calibrated.

- [FEASIBLE] Identity Anomaly (Impossible Travel / New Device) (TA0006.IDENTITY_ANOMALY, 0.85)
  Identity anomalies indicate possible account compromise.
  Evidence IDs: id-1, id-2

- [FEASIBLE] Suspicious LOLBin Execution Chain (TA0002.LOLBIN_CHAIN, 0.85)
  LOLBin execution following initial access suggests hands-on-keyboard activity.
  Evidence IDs: ep-1, ep-2

- [FEASIBLE] MFA Disable or Bypass (TA0004.MFA_BYPASS, 0.85)
  MFA changes combined with token anomalies indicate bypass.
  Evidence IDs: id-3, id-4

- [NOT FEASIBLE] Modify Authentication Process (TA0005.AUTH_PROCESS_MOD, 0.55)
  Decision: 
  Reason code: evidence_gap
  Authentication controls were altered to bypass access checks. Missing evidence: auth_process_modify
  Gap: This attack would require auth_process_modify but no such evidence was observed.
  Evidence IDs: id-3
  Missing Evidence:
  - auth_process_modify: Authentication process modified

- [NOT FEASIBLE] Impair Defenses (TA0005.IMPAIR_DEFENSES, 0.55)
  Decision: 
  Reason code: evidence_gap
  Defensive controls weakened to evade detection. Missing evidence: disable_logging, cloud_firewall_change
  Gap: This attack would require disable_logging, cloud_firewall_change but no such evidence was observed.
  Missing Evidence:
  - disable_logging: Security logging disabled or altered
  - cloud_firewall_change: Cloud firewall or security group opened

- [NOT FEASIBLE] Command and Control (TA0011.C2, 0.55)
  Decision: 
  Reason code: evidence_gap
  C2 established after initial access. Missing evidence: beacon_outbound, dns_tunneling
  Gap: This attack would require beacon_outbound, dns_tunneling but no such evidence was observed.
  Missing Evidence:
  - beacon_outbound: Outbound beacon to known C2
  - dns_tunneling: DNS tunneling patterns

- [NOT FEASIBLE] Admin Protocol Lateral Movement (TA0008.ADMIN_PROTOCOL_LATERAL, 0.55)
  Decision: 
  Reason code: evidence_gap
  Lateral movement over admin protocols with valid credentials. Missing evidence: new_inbound_admin_protocol, network_logon
  Gap: This attack would require new_inbound_admin_protocol, network_logon but no such evidence was observed.
  Missing Evidence:
  - new_inbound_admin_protocol: New inbound admin protocol used
  - network_logon: Successful network logon

- [NOT FEASIBLE] Privilege Escalation (TA0004.PRIVESCA, 0.55)
  Decision: 
  Reason code: evidence_gap
  Evidence of elevating access beyond initial privileges. Missing evidence: token_manipulation, admin_group_change
  Gap: This attack would require token_manipulation, admin_group_change but no such evidence was observed.
  Missing Evidence:
  - token_manipulation: Token manipulation activity
  - admin_group_change: User added to admin group

- [NOT FEASIBLE] Lateral Movement (TA0008.LATERAL, 0.55)
  Decision: 
  Reason code: evidence_gap
  Requires valid credentials before remote execution. Missing evidence: remote_service_creation, network_logon
  Gap: This attack would require remote_service_creation, network_logon but no such evidence was observed.
  Missing Evidence:
  - remote_service_creation: Remote service created
  - network_logon: Successful network logon

- [NOT FEASIBLE] Bulk Data Exfiltration (TA0010.BULK_EXFIL, 0.55)
  Decision: 
  Reason code: evidence_gap
  Bulk data access followed by outbound transfer. Missing evidence: bulk_download, large_outbound_transfer
  Gap: This attack would require bulk_download, large_outbound_transfer but no such evidence was observed.
  Missing Evidence:
  - bulk_download: Bulk data access or download
  - large_outbound_transfer: Large outbound data transfer

- [NOT FEASIBLE] Extended Persistence Mechanisms (TA0003.PERSIST_EXTENDED, 0.55)
  Decision: 
  Reason code: evidence_gap
  Persistence via registry and services after initial access. Missing evidence: registry_run_key
  Gap: This attack would require registry_run_key but no such evidence was observed.
  Evidence IDs: ep-3
  Missing Evidence:
  - registry_run_key: Registry run key set

- [NOT FEASIBLE] Valid Accounts Abuse (TA0006.VALID_ACCOUNTS, 0.55)
  Decision: 
  Reason code: evidence_gap
  Compromised valid accounts enable access without malware. Missing evidence: valid_account_login
  Gap: This attack would require valid_account_login but no such evidence was observed.
  Evidence IDs: id-2
  Missing Evidence:
  - valid_account_login: Login using valid credentials in unusual context

- [NOT FEASIBLE] Brute Force / Credential Stuffing (TA0006.BRUTE_FORCE, 0.55)
  Decision: 
  Reason code: evidence_gap
  High-volume authentication failures followed by access attempts. Missing evidence: password_spray, credential_stuffing
  Gap: This attack would require password_spray, credential_stuffing but no such evidence was observed.
  Missing Evidence:
  - password_spray: Password spraying pattern detected
  - credential_stuffing: Credential stuffing pattern detected

- [NOT FEASIBLE] Account Manipulation (TA0004.ACCOUNT_MANIP, 0.55)
  Decision: 
  Reason code: evidence_gap
  Account changes used to persist or elevate access. Missing evidence: account_manipulation, admin_group_change
  Gap: This attack would require account_manipulation, admin_group_change but no such evidence was observed.
  Missing Evidence:
  - account_manipulation: Account permissions or credentials modified
  - admin_group_change: User added to privileged group

- [NOT FEASIBLE] Initial Access via Phishing (TA0001.PHISHING, 0.55)
  Decision: 
  Reason code: evidence_gap
  User interaction and macro execution leading to outbound beaconing. Missing evidence: beacon_outbound
  Gap: This attack would require beacon_outbound but no such evidence was observed.
  Evidence IDs: ia-1, ia-2
  Missing Evidence:
  - beacon_outbound: Outbound beacon to known C2

- [NOT FEASIBLE] Application Layer Protocol C2 (TA0011.APP_LAYER_C2, 0.55)
  Decision: 
  Reason code: evidence_gap
  C2 over common application protocols for stealth. Missing evidence: app_layer_c2, beacon_outbound
  Gap: This attack would require app_layer_c2, beacon_outbound but no such evidence was observed.
  Missing Evidence:
  - app_layer_c2: C2 over web/mail/DNS protocols
  - beacon_outbound: Outbound beaconing to known C2

- [NOT FEASIBLE] Persistence (TA0003.PERSIST, 0.55)
  Decision: 
  Reason code: evidence_gap
  Persistence established after initial access. Missing evidence: registry_run_key, scheduled_task
  Gap: This attack would require registry_run_key, scheduled_task but no such evidence was observed.
  Missing Evidence:
  - registry_run_key: Registry run key set
  - scheduled_task: Scheduled task created

- [NOT FEASIBLE] Disable or Modify Security Logging (TA0005.LOG_TAMPER, 0.55)
  Decision: 
  Reason code: evidence_gap
  Disabling logging to hide attacker activity. Missing evidence: disable_logging, policy_bypass
  Gap: This attack would require disable_logging, policy_bypass but no such evidence was observed.
  Missing Evidence:
  - disable_logging: Security logging disabled
  - policy_bypass: Control policy bypassed

- [NOT FEASIBLE] Phishing via Link and OAuth Consent (TA0001.PHISH_LINK, 0.55)
  Decision: 
  Reason code: evidence_gap
  Link phishing followed by OAuth consent indicates account compromise. Missing evidence: phish_link_click, oauth_consent
  Gap: This attack would require phish_link_click, oauth_consent but no such evidence was observed.
  Missing Evidence:
  - phish_link_click: User clicked phishing link
  - oauth_consent: OAuth consent granted to suspicious app

- [NOT FEASIBLE] SaaS Admin Takeover (TA0004.SAAS_ADMIN, 0.55)
  Decision: 
  Reason code: evidence_gap
  Admin access gained through OAuth grants and role changes. Missing evidence: new_admin_role, oauth_app_grant
  Gap: This attack would require new_admin_role, oauth_app_grant but no such evidence was observed.
  Missing Evidence:
  - new_admin_role: Admin role granted
  - oauth_app_grant: High-privilege OAuth grant

- [NOT FEASIBLE] Inhibit System Recovery (TA0040.RECOVERY_INHIBIT, 0.55)
  Decision: 
  Reason code: evidence_gap
  Recovery features disabled to prevent restoration. Missing evidence: shadow_copy_delete
  Gap: This attack would require shadow_copy_delete but no such evidence was observed.
  Missing Evidence:
  - shadow_copy_delete: Shadow copies deleted

- [NOT FEASIBLE] Cloud Lateral Movement (TA0008.CLOUD_PIVOT, 0.55)
  Decision: 
  Reason code: evidence_gap
  Cross-account pivot using trust policy changes. Missing evidence: role_assume, trust_policy_change
  Gap: This attack would require role_assume, trust_policy_change but no such evidence was observed.
  Missing Evidence:
  - role_assume: Role assumed
  - trust_policy_change: Trust policy modified

- [NOT FEASIBLE] Supply Chain Compromise (TA0043.SUPPLY_CHAIN, 0.55)
  Decision: 
  Reason code: evidence_gap
  Build pipeline compromise with artifact tampering. Missing evidence: ci_runner_compromise, artifact_tamper
  Gap: This attack would require ci_runner_compromise, artifact_tamper but no such evidence was observed.
  Missing Evidence:
  - ci_runner_compromise: CI runner compromise
  - artifact_tamper: Build artifact tampering

- [NOT FEASIBLE] Insider Data Exfiltration (preconditions unmet) (TA0006.INSIDER_EXFIL, 0.40)
  Decision: 
  Reason code: precond_missing
  Large-scale access without compromise signals suggests insider misuse. Missing evidence: bulk_download, unusual_access_scope
  Gap: This attack would require bulk_download, unusual_access_scope but no such evidence was observed.
  Missing Evidence:
  - bulk_download: Bulk download or data access
  - unusual_access_scope: Unusual access scope

- [NOT FEASIBLE] Mailbox Rule Persistence (preconditions unmet) (TA0003.MAILBOX_PERSIST, 0.40)
  Decision: 
  Reason code: precond_missing
  Persistence through mailbox rules and forwarding. Missing evidence: mailbox_rule_create, forwarding_rule_set
  Gap: This attack would require mailbox_rule_create, forwarding_rule_set but no such evidence was observed.
  Missing Evidence:
  - mailbox_rule_create: Mailbox rule created
  - forwarding_rule_set: Auto-forwarding rule set

- [NOT FEASIBLE] Exfiltration Over Web Service (preconditions unmet) (TA0010.EXFIL_WEB, 0.40)
  Decision: 
  Reason code: precond_missing
  Exfiltration using legitimate web services. Missing evidence: exfil_web_service, large_outbound_transfer
  Gap: This attack would require exfil_web_service, large_outbound_transfer but no such evidence was observed.
  Missing Evidence:
  - exfil_web_service: Data exfil via web service
  - large_outbound_transfer: Large outbound data transfer

- [NOT FEASIBLE] Credential Dumping (preconditions unmet) (TA0006.CREDDUMP, 0.40)
  Decision: 
  Reason code: precond_missing
  Requires elevated privileges to access credential stores. Missing evidence: lsass_access
  Gap: This attack would require lsass_access but no such evidence was observed.
  Evidence IDs: ep-1
  Missing Evidence:
  - lsass_access: Access to LSASS

- [NOT FEASIBLE] Exfiltration (preconditions unmet) (TA0010.EXFIL, 0.40)
  Decision: 
  Reason code: precond_missing
  Exfiltration typically follows C2 and credential access. Missing evidence: data_staging, large_outbound_transfer
  Gap: This attack would require data_staging, large_outbound_transfer but no such evidence was observed.
  Missing Evidence:
  - data_staging: Data staged in archive
  - large_outbound_transfer: Large outbound data transfer

- [NOT FEASIBLE] Data Encrypted for Impact (admin approval required) (TA0040.IMPACT_ENCRYPT, 0.00)
  Decision: keep
  Reason code: admin_hold
  Rule pack gated by admin approval.
  Gap: Admin approval required to enable this rule pack.

- [NOT FEASIBLE] Network Evasion via Proxy/Tunnel (admin approval required) (TA0005.EVASION_C2, 0.00)
  Decision: keep
  Reason code: admin_hold
  Rule pack gated by admin approval.
  Gap: Admin approval required to enable this rule pack.

Reasoning Narrative:
- Incomplete: TA0001.PHISHING (Initial Access via Phishing) missing evidence beacon_outbound.
- Not feasible: TA0006.CREDDUMP (Credential Dumping) because preconditions are unmet.
- Incomplete: TA0008.LATERAL (Lateral Movement) missing evidence remote_service_creation, network_logon.
- Incomplete: TA0004.PRIVESCA (Privilege Escalation) missing evidence token_manipulation, admin_group_change.
- Incomplete: TA0003.PERSIST (Persistence) missing evidence registry_run_key, scheduled_task.
- Incomplete: TA0011.C2 (Command and Control) missing evidence beacon_outbound, dns_tunneling.
- Not feasible: TA0010.EXFIL (Exfiltration) because preconditions are unmet.
- Proved feasible: TA0006.IDENTITY_ANOMALY (Identity Anomaly (Impossible Travel / New Device)) with all preconditions and evidence satisfied.
- Proved feasible: TA0004.MFA_BYPASS (MFA Disable or Bypass) with all preconditions and evidence satisfied.
- Proved feasible: TA0002.LOLBIN_CHAIN (Suspicious LOLBin Execution Chain) with all preconditions and evidence satisfied.
- Incomplete: TA0003.PERSIST_EXTENDED (Extended Persistence Mechanisms) missing evidence registry_run_key.
- Incomplete: TA0006.VALID_ACCOUNTS (Valid Accounts Abuse) missing evidence valid_account_login.
- Incomplete: TA0006.BRUTE_FORCE (Brute Force / Credential Stuffing) missing evidence password_spray, credential_stuffing.
- Incomplete: TA0004.ACCOUNT_MANIP (Account Manipulation) missing evidence account_manipulation, admin_group_change.
- Incomplete: TA0005.AUTH_PROCESS_MOD (Modify Authentication Process) missing evidence auth_process_modify.
- Incomplete: TA0011.APP_LAYER_C2 (Application Layer Protocol C2) missing evidence app_layer_c2, beacon_outbound.
- Incomplete: TA0005.IMPAIR_DEFENSES (Impair Defenses) missing evidence disable_logging, cloud_firewall_change.
- Not feasible: TA0010.EXFIL_WEB (Exfiltration Over Web Service) because preconditions are unmet.
- Incomplete: TA0001.PHISH_LINK (Phishing via Link and OAuth Consent) missing evidence phish_link_click, oauth_consent.
- Not feasible: TA0003.MAILBOX_PERSIST (Mailbox Rule Persistence) because preconditions are unmet.
- Incomplete: TA0040.RECOVERY_INHIBIT (Inhibit System Recovery) missing evidence shadow_copy_delete.
- Not feasible: TA0006.INSIDER_EXFIL (Insider Data Exfiltration) because preconditions are unmet.
- Incomplete: TA0043.SUPPLY_CHAIN (Supply Chain Compromise) missing evidence ci_runner_compromise, artifact_tamper.
- Incomplete: TA0008.CLOUD_PIVOT (Cloud Lateral Movement) missing evidence role_assume, trust_policy_change.
- Incomplete: TA0004.SAAS_ADMIN (SaaS Admin Takeover) missing evidence new_admin_role, oauth_app_grant.
- Incomplete: TA0005.LOG_TAMPER (Disable or Modify Security Logging) missing evidence disable_logging, policy_bypass.
- Incomplete: TA0010.BULK_EXFIL (Bulk Data Exfiltration) missing evidence bulk_download, large_outbound_transfer.
- Incomplete: TA0008.ADMIN_PROTOCOL_LATERAL (Admin Protocol Lateral Movement) missing evidence new_inbound_admin_protocol, network_logon.

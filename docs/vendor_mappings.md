# Vendor Field Normalization Map

This document summarizes how Aman normalizes vendor-specific fields into internal event types.

## Elastic ECS (`elastic_ecs`)
- `event.category=process` + `event.type=start` -> `process_creation`
- `event.category=file` + `event.type=creation` -> `file_create`
- `event.category=file` + `event.type=deletion` -> `file_delete`
- `event.category=file` + `event.type=change|modify` -> `file_modify`
- `event.category=registry` + `event.type=change|creation` -> `registry_change`
- `event.category=registry` + `event.action` contains `run` -> `registry_run_key`
- `event.category=iam` -> `iam_change`
- `event.category=iam` + `event.action` contains `group|admin|role` -> `admin_group_change`
- `event.category=iam` + `event.action` contains `policy|trust` -> `policy_override`
- `event.category=authentication` + `event.action` contains `impossible_travel` -> `impossible_travel`
- `event.category=authentication` + `event.action` contains `new_device` -> `new_device_login`
- `event.category=authentication` + `event.action` contains `mfa` + `disable|reset|bypass` -> `mfa_disabled`
- `event.category=authentication` + `event.action` contains `token` + `refresh|replay` -> `token_refresh_anomaly`
- `event.category=authentication` default -> `valid_account_login`
- `destination.port` in `22,445,3389,5985,5986` -> `new_inbound_admin_protocol`
- Otherwise: `event.action` or first `event.type`/`event.category`

Key fields:
- Host: `host.name`
- User: `user.name`
- Time: `@timestamp`
- Details: `labels`, `message`, `event.kind`

## Splunk CIM Auth (`splunk_cim_auth`)
- Type mapping:
  - `impossible travel` -> `impossible_travel`
  - `new device` -> `new_device_login`
  - `mfa` + `disable|reset|bypass` -> `mfa_disabled`
  - `token` + `refresh|replay` -> `token_refresh_anomaly`
  - `password spray` -> `password_spray`
  - `credential stuffing` -> `credential_stuffing`
  - `admin group|role change` -> `admin_group_change`
  - `oauth|consent` -> `oauth_consent`
  - otherwise: `action` or `signature`
- User: `user` or `src_user` or `dest_user`
- Host: `dest`
- Time: `_time`
- Details: `src`, `dest`, `app`, `signature`, `fields`

## Splunk CIM Net (`splunk_cim_net`)
- Type mapping:
  - `dest_port` in `22,445,3389,5985,5986` -> `new_inbound_admin_protocol`
  - `bytes_out` > 10MB -> `large_outbound_transfer`
  - otherwise: `action` or `transport`
- Host: `dest`
- Time: `_time`
- Details: `src`, `dest`, `src_port`, `dest_port`, `transport`, `bytes_in`, `bytes_out`, `fields`

## Microsoft Defender for Endpoint (MDE)
### Device Events (`mde`, kind=`device`)
- Type mapping:
  - `ProcessCreated` -> `process_creation`
  - `CommandLine` contains `rundll32|mshta|certutil|regsvr32` -> `lolbin_execution`
  - `CommandLine` contains `lsass` -> `lsass_access`
  - `ServiceInstalled|ServiceCreated` -> `service_install`
  - `Registry*` + `\\Run` -> `registry_run_key`
  - MFA/token changes -> `mfa_disabled` / `token_refresh_anomaly`
  - otherwise: `ActionType`
- Host: `DeviceName`
- User: `AccountName`
- Time: `Timestamp`
- Details: `AdditionalFields`

### Identity Events (`mde`, kind=`identity`)
- Type mapping:
  - `ActionType` (same mapping rules as device events when present)
  - `MFAReset|MFABypass|MFADisabled` -> `mfa_disabled`
  - `AddUserToGroup|AddMemberToGroup` -> `admin_group_change`
  - `OAuthGrant|TokenRefresh` -> `token_refresh_anomaly`
  - default: `identity_event`
- Host: `DeviceName`
- User: `TargetAccountUpn` or `AccountDisplayName` or `AccountName`
- Time: `Timestamp`
- Details: `AdditionalFields`

## Okta System Log (`okta_systemlog`)
- Type mapping:
  - `impossible_travel` -> `impossible_travel`
  - `new_device` -> `new_device_login`
  - `user.mfa.factor.deactivate|reset|suspend` -> `mfa_disabled`
  - `token` + `refresh|revoke` -> `token_refresh_anomaly`
  - `oauth` + `consent` -> `oauth_consent`
  - `user.session.start|user.authentication*` -> `valid_account_login`
  - `admin role` -> `new_admin_role`
  - `user.lifecycle*` -> `iam_change`
  - `group.user_membership*` -> `admin_group_change`
  - `policy.rule*` -> `policy_override`
  - otherwise -> `eventType`
- User: `actor.alternateId` or `actor.displayName` or `actor.id`
- Time: `published`
- Details: `client.ipAddress`, `client.userAgent`, `actor.id`, `target`

## AWS CloudTrail (`aws_cloudtrail`)
- Type mapping:
  - `eventSource` contains `iam.amazonaws.com` or `sts.amazonaws.com`:
    - `CreateUser|CreateRole|CreatePolicy` -> `new_admin_account`
    - `AddUserToGroup|AttachGroupPolicy` -> `admin_group_change`
    - `AttachRolePolicy|PutRolePolicy|PutUserPolicy` -> `policy_override`
    - `UpdateAssumeRolePolicy|AssumeRolePolicy|UpdateTrustPolicy` -> `trust_boundary_change`
    - `AssumeRole` -> `role_assume`
    - otherwise -> `iam_change`
  - `eventSource` contains `ec2.amazonaws.com` + `AuthorizeSecurityGroupIngress|Egress` -> `new_firewall_rule`
  - otherwise -> `eventName`
- User: `userIdentity.arn` or `userIdentity.userName` or `userIdentity.principalId`
- Host: `recipientAccountId`
- Time: `eventTime`
- Details: `eventSource`, `awsRegion`, `sourceIPAddress`, `userAgent`, `requestParameters`, `responseElements`

## Microsoft Sentinel CSL (`sentinel_csl`)
- Type mapping:
  - `Fields.CommandLine` contains `rundll32|mshta|certutil|regsvr32` -> `lolbin_execution`
  - `Fields.CommandLine` contains `lsass` -> `lsass_access`
  - `Fields.ProcessName` or `Fields.CommandLine` -> `process_creation`
  - `Fields.FileName` or `Fields.FilePath` -> `file_change`
  - `Fields.RegistryKey` contains `\\Run` -> `registry_run_key`
  - `Fields.RegistryKey` or `Fields.RegistryValue` -> `registry_change`
  - `Fields.ServiceName|ServiceFileName` -> `service_install`
  - `Activity|DeviceAction` contains `AuthenticationSuccess` -> `authentication_success`
  - `Activity|DeviceAction` contains `AuthenticationFailure` -> `authentication_failure`
  - otherwise -> `Activity` or `DeviceAction`
- Host: `Computer`
- User: `AccountName`
- Time: `TimeGenerated`
- Details: `SourceIP`, `DestinationIP`, `Protocol`, `Fields`

## CrowdStrike FDR (`crowdstrike_fdr`)
- Type mapping:
  - `ProcessRollup2|ProcessRollup` + LOLBin commandline -> `lolbin_execution`
  - `ProcessRollup2|ProcessRollup` + `lsass` -> `lsass_access`
  - `ProcessRollup2|ProcessRollup` -> `process_creation`
  - `FileCreateInfo` -> `file_create`
  - `FileWriteInfo` -> `file_modify`
  - `FileDeleteInfo` -> `file_delete`
  - `RegistryValueSet|RegistryKeyCreated` + `\\Run` -> `registry_run_key`
  - `RegistryValueSet|RegistryKeyCreated` -> `registry_change`
  - `ServiceInstalled|ServiceCreate` -> `service_install`
  - otherwise -> `event_simpleName`
- Host: `ComputerName`
- User: `UserName`
- Time: `timestamp` or `ContextTimeStamp` (unix ms)
- Details: `aid`, `aip`, `details`

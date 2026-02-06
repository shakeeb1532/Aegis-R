# Vendor Field Normalization Map

This document summarizes how Aegis-R normalizes vendor-specific fields into internal event types.

## Elastic ECS (`elastic_ecs`)
- `event.category=process` + `event.type=start` -> `process_creation`
- `event.category=file` + `event.type=creation` -> `file_create`
- `event.category=file` + `event.type=deletion` -> `file_delete`
- `event.category=file` + `event.type=change|modify` -> `file_modify`
- `event.category=registry` + `event.type=change|creation` -> `registry_change`
- `event.category=iam` -> `iam_change`
- Otherwise: `event.action` or first `event.type`/`event.category`

Key fields:
- Host: `host.name`
- User: `user.name`
- Time: `@timestamp`
- Details: `labels`, `message`, `event.kind`

## Splunk CIM Auth (`splunk_cim_auth`)
- Type: `action` or `signature` or `authentication`
- User: `user` or `src_user` or `dest_user`
- Host: `dest`
- Time: `_time`
- Details: `src`, `dest`, `app`, `signature`, `fields`

## Splunk CIM Net (`splunk_cim_net`)
- Type: `action` or `transport` or `network`
- Host: `dest`
- Time: `_time`
- Details: `src`, `dest`, `src_port`, `dest_port`, `transport`, `bytes_in`, `bytes_out`, `fields`

## Microsoft Defender for Endpoint (MDE)
### Device Events (`mde`, kind=`device`)
- Type: `ActionType`
- Host: `DeviceName`
- User: `AccountName`
- Time: `Timestamp`
- Details: `AdditionalFields`

### Identity Events (`mde`, kind=`identity`)
- Type: `identity_event`
- Host: `DeviceName`
- User: `TargetAccountUpn` or `AccountDisplayName` or `AccountName`
- Time: `Timestamp`
- Details: `AdditionalFields`

## Okta System Log (`okta_systemlog`)
- Type mapping:
  - `user.lifecycle*` -> `iam_change`
  - `group.user_membership*` -> `iam_change`
  - `policy.rule*` -> `policy_override`
  - otherwise -> `eventType`
- User: `actor.alternateId` or `actor.displayName` or `actor.id`
- Time: `published`
- Details: `client.ipAddress`, `client.userAgent`, `actor.id`, `target`

## AWS CloudTrail (`aws_cloudtrail`)
- Type mapping:
  - `eventSource` contains `iam.amazonaws.com` or `sts.amazonaws.com` -> `iam_change`
  - `eventName` contains `CreateUser` or `CreateRole` -> `new_admin_account`
  - otherwise -> `eventName`
- User: `userIdentity.arn` or `userIdentity.userName` or `userIdentity.principalId`
- Host: `recipientAccountId`
- Time: `eventTime`
- Details: `eventSource`, `awsRegion`, `sourceIPAddress`, `userAgent`, `requestParameters`, `responseElements`

## Microsoft Sentinel CSL (`sentinel_csl`)
- Type mapping:
  - `Fields.ProcessName` or `Fields.CommandLine` -> `process_creation`
  - `Fields.FileName` or `Fields.FilePath` -> `file_change`
  - `Fields.RegistryKey` or `Fields.RegistryValue` -> `registry_change`
  - otherwise -> `Activity` or `DeviceAction`
- Host: `Computer`
- User: `AccountName`
- Time: `TimeGenerated`
- Details: `SourceIP`, `DestinationIP`, `Protocol`, `Fields`

## CrowdStrike FDR (`crowdstrike_fdr`)
- Type mapping:
  - `ProcessRollup2|ProcessRollup` -> `process_creation`
  - `FileCreateInfo` -> `file_create`
  - `FileWriteInfo` -> `file_modify`
  - `FileDeleteInfo` -> `file_delete`
  - `RegistryValueSet|RegistryKeyCreated` -> `registry_change`
  - otherwise -> `event_simpleName`
- Host: `ComputerName`
- User: `UserName`
- Time: `timestamp` or `ContextTimeStamp` (unix ms)
- Details: `aid`, `aip`, `details`

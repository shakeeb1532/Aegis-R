package integration

import (
	"os"
	"path/filepath"
	"testing"

	"aman/internal/model"
	"aman/internal/testutil"
)

func assertHasType(t *testing.T, events []EventLike, typ string) {
	t.Helper()
	for _, e := range events {
		if e.Type == typ {
			return
		}
	}
	t.Fatalf("expected type %s", typ)
}

type EventLike struct {
	Type string
}

func TestMappingElasticECS(t *testing.T) {
	root := testutil.RepoRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "data", "fixtures", "elastic_ecs.json"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	events, err := IngestEvents(data, IngestOptions{Schema: SchemaElasticECS})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	assertHasType(t, toLike(events), "impossible_travel")
	assertHasType(t, toLike(events), "new_device_login")
	assertHasType(t, toLike(events), "lsass_access")
	assertHasType(t, toLike(events), "registry_run_key")
	assertHasType(t, toLike(events), "file_create")
	assertHasType(t, toLike(events), "file_delete")
	assertHasType(t, toLike(events), "file_modify")
	assertHasType(t, toLike(events), "registry_change")
	assertHasType(t, toLike(events), "mfa_method_removed")
	assertHasType(t, toLike(events), "token_refresh_anomaly")
	assertHasType(t, toLike(events), "admin_group_change")
	assertHasType(t, toLike(events), "policy_override")
}

func TestMappingOkta(t *testing.T) {
	root := testutil.RepoRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "data", "fixtures", "okta_systemlog.json"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	events, err := IngestEvents(data, IngestOptions{Schema: SchemaOkta})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	assertHasType(t, toLike(events), "signin_success")
	assertHasType(t, toLike(events), "mfa_method_removed")
	assertHasType(t, toLike(events), "admin_group_change")
	assertHasType(t, toLike(events), "oauth_consent")
	assertHasType(t, toLike(events), "token_refresh_anomaly")
	assertHasType(t, toLike(events), "policy_override")
	assertHasType(t, toLike(events), "iam_change")
	assertHasType(t, toLike(events), "new_admin_role")
}

func TestMappingCloudTrail(t *testing.T) {
	root := testutil.RepoRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "data", "fixtures", "aws_cloudtrail.json"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	events, err := IngestEvents(data, IngestOptions{Schema: SchemaCloudTrail})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	assertHasType(t, toLike(events), "admin_group_change")
	assertHasType(t, toLike(events), "new_firewall_rule")
	assertHasType(t, toLike(events), "trust_boundary_change")
	assertHasType(t, toLike(events), "policy_override")
	assertHasType(t, toLike(events), "policy_change")
	assertHasType(t, toLike(events), "role_assume")
}

func TestMappingSplunkAuth(t *testing.T) {
	root := testutil.RepoRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "data", "fixtures", "splunk_cim_auth.json"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	events, err := IngestEvents(data, IngestOptions{Schema: SchemaSplunkAuth})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	assertHasType(t, toLike(events), "impossible_travel")
	assertHasType(t, toLike(events), "password_spray")
	assertHasType(t, toLike(events), "credential_stuffing")
	assertHasType(t, toLike(events), "token_refresh_anomaly")
}

func TestMappingSplunkNet(t *testing.T) {
	root := testutil.RepoRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "data", "fixtures", "splunk_cim_net.json"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	events, err := IngestEvents(data, IngestOptions{Schema: SchemaSplunkNet})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	seen := toLike(events)
	hasAdmin := false
	hasExfil := false
	for _, e := range seen {
		if e.Type == "new_inbound_admin_protocol" {
			hasAdmin = true
		}
		if e.Type == "large_outbound_transfer" {
			hasExfil = true
		}
	}
	if !hasAdmin || !hasExfil {
		t.Fatalf("expected both admin protocol and large transfer; got admin=%v exfil=%v", hasAdmin, hasExfil)
	}
}

func TestMappingCrowdStrike(t *testing.T) {
	root := testutil.RepoRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "data", "fixtures", "crowdstrike_fdr.json"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	events, err := IngestEvents(data, IngestOptions{Schema: SchemaCrowdStrike})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	assertHasType(t, toLike(events), "lolbin_execution")
	assertHasType(t, toLike(events), "registry_run_key")
	assertHasType(t, toLike(events), "service_install")
	assertHasType(t, toLike(events), "file_create")
	assertHasType(t, toLike(events), "file_modify")
	assertHasType(t, toLike(events), "file_delete")
}

func TestMappingSentinel(t *testing.T) {
	root := testutil.RepoRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "data", "fixtures", "sentinel_csl.json"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	events, err := IngestEvents(data, IngestOptions{Schema: SchemaSentinelCSL})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	assertHasType(t, toLike(events), "lolbin_execution")
	assertHasType(t, toLike(events), "registry_run_key")
	assertHasType(t, toLike(events), "service_install")
}

func TestMappingMDE(t *testing.T) {
	root := testutil.RepoRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "data", "fixtures", "mde_device.json"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	events, err := IngestEvents(data, IngestOptions{Schema: SchemaMDE, Kind: "device"})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	assertHasType(t, toLike(events), "lolbin_execution")
	assertHasType(t, toLike(events), "service_install")
	assertHasType(t, toLike(events), "registry_run_key")
}

func TestMappingMDEIdentity(t *testing.T) {
	root := testutil.RepoRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "data", "fixtures", "mde_identity.json"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	events, err := IngestEvents(data, IngestOptions{Schema: SchemaMDE, Kind: "identity"})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	assertHasType(t, toLike(events), "mfa_method_removed")
	assertHasType(t, toLike(events), "admin_group_change")
	assertHasType(t, toLike(events), "token_refresh_anomaly")
}

func TestMappingSysmonJSON(t *testing.T) {
	root := testutil.RepoRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "data", "fixtures", "sysmon_windows.json"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	events, err := IngestEvents(data, IngestOptions{Schema: SchemaSysmonJSON})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	assertHasType(t, toLike(events), "process_creation")
	assertHasType(t, toLike(events), "lolbin_execution")
	assertHasType(t, toLike(events), "registry_run_key")
	assertHasType(t, toLike(events), "service_install")
	assertHasType(t, toLike(events), "disable_logging")
	assertHasType(t, toLike(events), "wmi_subscription_trigger")
}

func TestMappingWindowsSecurityJSON(t *testing.T) {
	root := testutil.RepoRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "data", "fixtures", "windows_security.json"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	events, err := IngestEvents(data, IngestOptions{Schema: SchemaWindowsSec})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	seen := toLike(events)
	assertHasType(t, seen, "signin_success")
	assertHasType(t, seen, "valid_account_login")
	assertHasType(t, seen, "network_logon")
	assertHasType(t, seen, "signin_denied_account_state")
	assertHasType(t, seen, "network_logon_failure")
	assertHasType(t, seen, "admin_protocol_denied")
	assertHasType(t, seen, "admin_group_change")
	assertHasType(t, seen, "disable_logging")
}

func TestMappingBOTSWindowsSecurityJSON(t *testing.T) {
	root := testutil.RepoRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "data", "fixtures", "botsv1_windows_security.json"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	events, err := IngestEvents(data, IngestOptions{Schema: SchemaWindowsSec})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	seen := toLike(events)
	assertHasType(t, seen, "signin_success")
	assertHasType(t, seen, "valid_account_login")
	assertHasType(t, seen, "network_logon")
	assertHasType(t, seen, "process_creation")
}

func TestMappingBOTSSysmonJSON(t *testing.T) {
	root := testutil.RepoRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "data", "fixtures", "botsv1_sysmon.json"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	events, err := IngestEvents(data, IngestOptions{Schema: SchemaSysmonJSON})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	seen := toLike(events)
	assertHasType(t, seen, "process_creation")
	assertHasType(t, seen, "network_connection")
}

func TestMappingAttackDataWindowsSecurityJSON(t *testing.T) {
	root := testutil.RepoRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "data", "fixtures", "attack_data_t1053_security.json"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	events, err := IngestEvents(data, IngestOptions{Schema: SchemaWindowsSec})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	seen := toLike(events)
	assertHasType(t, seen, "signin_success")
	assertHasType(t, seen, "valid_account_login")
	assertHasType(t, seen, "explicit_credential_use")
	assertHasType(t, seen, "privileged_logon")
	assertHasType(t, seen, "kerberos_ticket")
}

func TestMappingAttackDataSysmonJSON(t *testing.T) {
	root := testutil.RepoRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "data", "fixtures", "attack_data_t1053_sysmon.json"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	events, err := IngestEvents(data, IngestOptions{Schema: SchemaSysmonJSON})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	seen := toLike(events)
	assertHasType(t, seen, "lsass_access")
	assertHasType(t, seen, "schtasks_create")
	assertHasType(t, seen, "scheduled_task")
	assertHasType(t, seen, "process_creation")
	assertHasType(t, seen, "registry_change")
	assertHasType(t, seen, "network_connection")
}


func TestMappingAttackDataT1053BlockerWindowsSecurityJSON(t *testing.T) {
	root := testutil.RepoRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "data", "fixtures", "attack_data_t1053_blocker_windows_security.json"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	events, err := IngestEvents(data, IngestOptions{Schema: SchemaWindowsSec})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	seen := toLike(events)
	assertHasType(t, seen, "service_install")
	assertHasType(t, seen, "signin_failed_auth")
	assertHasType(t, seen, "network_logon_failure")
	assertHasType(t, seen, "admin_protocol_denied")
}

func TestMappingAttackDataT1047WindowsSecurityJSON(t *testing.T) {
	root := testutil.RepoRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "data", "fixtures", "attack_data_t1047_security.json"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	events, err := IngestEvents(data, IngestOptions{Schema: SchemaWindowsSec})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	seen := toLike(events)
	assertHasType(t, seen, "signin_success")
	assertHasType(t, seen, "valid_account_login")
	assertHasType(t, seen, "explicit_credential_use")
	assertHasType(t, seen, "privileged_logon")
	assertHasType(t, seen, "kerberos_ticket")
}

func TestMappingAttackDataT1047SysmonJSON(t *testing.T) {
	root := testutil.RepoRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "data", "fixtures", "attack_data_t1047_sysmon.json"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	events, err := IngestEvents(data, IngestOptions{Schema: SchemaSysmonJSON})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	seen := toLike(events)
	assertHasType(t, seen, "process_access")
	assertHasType(t, seen, "process_creation")
	assertHasType(t, seen, "lolbin_execution")
	assertHasType(t, seen, "wmic_process_create")
}

func TestMappingAttackDataT1027WindowsSecurityJSON(t *testing.T) {
	root := testutil.RepoRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "data", "fixtures", "attack_data_t1027_security.json"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	events, err := IngestEvents(data, IngestOptions{Schema: SchemaWindowsSec})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	seen := toLike(events)
	assertHasType(t, seen, "signin_success")
	assertHasType(t, seen, "valid_account_login")
	assertHasType(t, seen, "explicit_credential_use")
	assertHasType(t, seen, "privileged_logon")
	assertHasType(t, seen, "kerberos_ticket")
}

func TestMappingAttackDataT1027SysmonJSON(t *testing.T) {
	root := testutil.RepoRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "data", "fixtures", "attack_data_t1027_sysmon.json"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	events, err := IngestEvents(data, IngestOptions{Schema: SchemaSysmonJSON})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	seen := toLike(events)
	assertHasType(t, seen, "process_creation")
	assertHasType(t, seen, "script_execution")
	assertHasType(t, seen, "encoded_command")
	assertHasType(t, seen, "encoded_powershell")
	assertHasType(t, seen, "new_inbound_admin_protocol")
	assertHasType(t, seen, "lsass_access")
	assertHasType(t, seen, "file_create")
}

func TestMappingSentinelAuth(t *testing.T) {
	root := testutil.RepoRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "data", "fixtures", "sentinel_csl.json"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	events, err := IngestEvents(data, IngestOptions{Schema: SchemaSentinelCSL})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	assertHasType(t, toLike(events), "signin_success")
	assertHasType(t, toLike(events), "signin_failed_auth")
}

func TestMappingSentinelAuthPolicyAndAccountState(t *testing.T) {
	data := []byte(`[
	  {
	    "TimeGenerated": "2026-02-06T12:43:30Z",
	    "Computer": "win-02",
	    "AccountName": "jill",
	    "DeviceAction": "AuthenticationFailure",
	    "Activity": "AuthenticationFailure",
	    "Fields": {"Result": "BlockedByPolicy", "Message": "Conditional Access policy blocked sign-in"}
	  },
	  {
	    "TimeGenerated": "2026-02-06T12:44:00Z",
	    "Computer": "win-02",
	    "AccountName": "jill",
	    "DeviceAction": "AuthenticationFailure",
	    "Activity": "AuthenticationFailure",
	    "Fields": {"Result": "AccountDisabled", "Message": "Account disabled"}
	  }
	]`)
	events, err := IngestEvents(data, IngestOptions{Schema: SchemaSentinelCSL})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	assertHasType(t, toLike(events), "signin_denied_policy")
	assertHasType(t, toLike(events), "signin_denied_account_state")
}

func toLike(events []model.Event) []EventLike {
	out := make([]EventLike, 0, len(events))
	for _, e := range events {
		out = append(out, EventLike{Type: e.Type})
	}
	return out
}

func TestMappingCloudTrailBlockers(t *testing.T) {
	data := []byte(`[
	  {
	    "eventID": "ct-b1",
	    "eventTime": "2026-02-06T12:37:00Z",
	    "eventSource": "cloudtrail.amazonaws.com",
	    "eventName": "StopLogging",
	    "awsRegion": "us-east-1",
	    "recipientAccountId": "123456789012",
	    "userIdentity": {"userName": "secops"},
	    "errorCode": "AccessDenied",
	    "errorMessage": "Access denied"
	  },
	  {
	    "eventID": "ct-b2",
	    "eventTime": "2026-02-06T12:38:00Z",
	    "eventSource": "iam.amazonaws.com",
	    "eventName": "AttachRolePolicy",
	    "awsRegion": "us-east-1",
	    "recipientAccountId": "123456789012",
	    "userIdentity": {"userName": "secops"},
	    "errorCode": "AccessDenied",
	    "errorMessage": "User is not authorized to perform iam:AttachRolePolicy"
	  }
	]`)
	events, err := IngestEvents(data, IngestOptions{Schema: SchemaCloudTrail})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	assertHasType(t, toLike(events), "logging_verified_intact")
	assertHasType(t, toLike(events), "admin_action_denied")
}

func TestMappingCloudTrailSuccessfulLogTamper(t *testing.T) {
	data := []byte(`[
	  {
	    "eventID": "ct-s1",
	    "eventTime": "2026-02-06T12:37:00Z",
	    "eventSource": "cloudtrail.amazonaws.com",
	    "eventName": "StopLogging",
	    "awsRegion": "us-east-1",
	    "recipientAccountId": "123456789012",
	    "userIdentity": {"userName": "secops"}
	  },
	  {
	    "eventID": "ct-s2",
	    "eventTime": "2026-02-06T12:38:00Z",
	    "eventSource": "cloudtrail.amazonaws.com",
	    "eventName": "UpdateTrail",
	    "awsRegion": "us-east-1",
	    "recipientAccountId": "123456789012",
	    "userIdentity": {"userName": "secops"}
	  }
	]`)
	events, err := IngestEvents(data, IngestOptions{Schema: SchemaCloudTrail})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	assertHasType(t, toLike(events), "disable_logging")
	assertHasType(t, toLike(events), "policy_bypass")
}

func TestMappingCloudTrailConsoleLoginSuccessAndMFAState(t *testing.T) {
	data := []byte(`[
	  {
	    "eventID": "ct-login-1",
	    "eventTime": "2026-02-06T12:37:00Z",
	    "eventSource": "signin.amazonaws.com",
	    "eventName": "ConsoleLogin",
	    "awsRegion": "us-east-1",
	    "recipientAccountId": "123456789012",
	    "userIdentity": {"userName": "secops"},
	    "responseElements": {"ConsoleLogin": "Success"},
	    "additionalEventData": {"MFAUsed": "No"}
	  },
	  {
	    "eventID": "ct-login-2",
	    "eventTime": "2026-02-06T12:38:00Z",
	    "eventSource": "signin.amazonaws.com",
	    "eventName": "ConsoleLogin",
	    "awsRegion": "us-east-1",
	    "recipientAccountId": "123456789012",
	    "userIdentity": {"userName": "secops"},
	    "responseElements": {"ConsoleLogin": "Success"},
	    "additionalEventData": {"MFAUsed": "Yes"}
	  }
	]`)
	events, err := IngestEvents(data, IngestOptions{Schema: SchemaCloudTrail})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	assertHasType(t, toLike(events), "signin_success")
	assertHasType(t, toLike(events), "mfa_not_required")
	assertHasType(t, toLike(events), "mfa_success")
}

func TestMappingCloudTrailIAMMFAChanges(t *testing.T) {
	data := []byte(`[
	  {
	    "eventID": "ct-mfa-1",
	    "eventTime": "2026-02-06T12:37:00Z",
	    "eventSource": "iam.amazonaws.com",
	    "eventName": "DeleteVirtualMFADevice",
	    "awsRegion": "us-east-1",
	    "recipientAccountId": "123456789012",
	    "userIdentity": {"userName": "secops"}
	  },
	  {
	    "eventID": "ct-mfa-2",
	    "eventTime": "2026-02-06T12:38:00Z",
	    "eventSource": "iam.amazonaws.com",
	    "eventName": "CreateVirtualMFADevice",
	    "awsRegion": "us-east-1",
	    "recipientAccountId": "123456789012",
	    "userIdentity": {"userName": "secops"}
	  }
	]`)
	events, err := IngestEvents(data, IngestOptions{Schema: SchemaCloudTrail})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	assertHasType(t, toLike(events), "mfa_method_removed")
	assertHasType(t, toLike(events), "mfa_policy_changed")
}

func TestMappingCloudTrailFailedIAMMutationDoesNotLookSuccessful(t *testing.T) {
	data := []byte(`[
	  {
	    "eventID": "ct-f1",
	    "eventTime": "2026-02-06T12:38:00Z",
	    "eventSource": "iam.amazonaws.com",
	    "eventName": "DeleteGroup",
	    "awsRegion": "us-east-1",
	    "recipientAccountId": "123456789012",
	    "userIdentity": {"userName": "secops"},
	    "errorCode": "DeleteConflictException",
	    "errorMessage": "Cannot delete entity, must remove users from group first."
	  }
	]`)
	events, err := IngestEvents(data, IngestOptions{Schema: SchemaCloudTrail})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Type == "iam_change" {
		t.Fatalf("failed IAM mutation should not normalize to iam_change")
	}
	if events[0].Type != "access_denied" {
		t.Fatalf("expected conservative failed-IAM normalization, got %q", events[0].Type)
	}
}

func TestMappingCloudTrailDeletePolicyIsPolicyChange(t *testing.T) {
	data := []byte(`[
	  {
	    "eventID": "ct-p1",
	    "eventTime": "2026-02-06T12:38:00Z",
	    "eventSource": "iam.amazonaws.com",
	    "eventName": "DeletePolicy",
	    "awsRegion": "us-east-1",
	    "recipientAccountId": "123456789012",
	    "userIdentity": {"userName": "secops"}
	  }
	]`)
	events, err := IngestEvents(data, IngestOptions{Schema: SchemaCloudTrail})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Type != "policy_change" {
		t.Fatalf("expected DeletePolicy to normalize to policy_change, got %q", events[0].Type)
	}
}

func TestMappingSentinelBlockers(t *testing.T) {
	data := []byte(`[
	  {
	    "TimeGenerated": "2026-02-06T12:40:00Z",
	    "Computer": "win-02",
	    "AccountName": "jill",
	    "SourceIP": "10.0.0.15",
	    "DestinationIP": "10.0.0.16",
	    "DeviceAction": "ExecutionBlocked",
	    "Activity": "ExecutionBlocked",
	    "Protocol": "tcp",
	    "Fields": {"ProcessName": "mshta.exe", "Reason": "AppLocker blocked execution"}
	  },
	  {
	    "TimeGenerated": "2026-02-06T12:41:00Z",
	    "Computer": "win-02",
	    "AccountName": "jill",
	    "SourceIP": "10.0.0.15",
	    "DestinationIP": "10.0.0.16",
	    "DeviceAction": "RegistryWriteBlocked",
	    "Activity": "RegistryWriteBlocked",
	    "Protocol": "tcp",
	    "Fields": {"RegistryKey": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "Result": "Blocked"}
	  }
	]`)
	events, err := IngestEvents(data, IngestOptions{Schema: SchemaSentinelCSL})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	assertHasType(t, toLike(events), "application_whitelisted")
	assertHasType(t, toLike(events), "registry_write_blocked")
}

func TestMappingElasticECSBlockers(t *testing.T) {
	data := []byte(`[
	  {
	    "@timestamp": "2026-02-06T12:20:00Z",
	    "event": {"id": "ecs-b1", "action": "execution_blocked", "category": ["process"], "type": ["denied"], "kind": "alert"},
	    "host": {"name": "host-1"},
	    "user": {"name": "frank"},
	    "message": "AppLocker blocked execution of mshta.exe",
	    "labels": {"status": "blocked"}
	  },
	  {
	    "@timestamp": "2026-02-06T12:21:00Z",
	    "event": {"id": "ecs-b2", "action": "firewall_outbound_denied", "category": ["network"], "type": ["denied"], "kind": "alert"},
	    "host": {"name": "host-1"},
	    "user": {"name": "frank"},
	    "message": "Firewall outbound blocked to 198.51.100.2",
	    "labels": {"status": "denied"}
	  }
	]`)
	events, err := IngestEvents(data, IngestOptions{Schema: SchemaElasticECS})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	assertHasType(t, toLike(events), "application_whitelisted")
	assertHasType(t, toLike(events), "firewall_block_outbound")
}

func TestMappingSplunkBlockers(t *testing.T) {
	auth := []byte(`[
	  {
	    "_time": "2026-02-06T12:25:00Z",
	    "user": "gina",
	    "src": "198.51.100.5",
	    "dest": "idp-02",
	    "action": "access denied",
	    "app": "okta",
	    "signature": "admin action denied",
	    "fields": {"message": "admin action denied by policy"}
	  }
	]`)
	events, err := IngestEvents(auth, IngestOptions{Schema: SchemaSplunkAuth})
	if err != nil {
		t.Fatalf("ingest auth: %v", err)
	}
	assertHasType(t, toLike(events), "admin_action_denied")

	net := []byte(`[
	  {
	    "_time": "2026-02-06T12:28:00Z",
	    "src": "10.0.0.5",
	    "dest": "app-10",
	    "src_port": 51515,
	    "dest_port": 443,
	    "transport": "tcp",
	    "action": "firewall outbound blocked",
	    "bytes_in": 1024,
	    "bytes_out": 250,
	    "fields": {"sensor": "netflow"}
	  }
	]`)
	events, err = IngestEvents(net, IngestOptions{Schema: SchemaSplunkNet})
	if err != nil {
		t.Fatalf("ingest net: %v", err)
	}
	assertHasType(t, toLike(events), "firewall_block_outbound")
}

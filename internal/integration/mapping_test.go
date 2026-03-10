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
	assertHasType(t, toLike(events), "authentication_success")
	assertHasType(t, toLike(events), "authentication_failure")
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

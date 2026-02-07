package integration

import (
	"os"
	"path/filepath"
	"testing"

	"aegisr/internal/model"
	"aegisr/internal/testutil"
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
	assertHasType(t, toLike(events), "valid_account_login")
	assertHasType(t, toLike(events), "mfa_disabled")
	assertHasType(t, toLike(events), "admin_group_change")
	assertHasType(t, toLike(events), "oauth_consent")
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
}

func toLike(events []model.Event) []EventLike {
	out := make([]EventLike, 0, len(events))
	for _, e := range events {
		out = append(out, EventLike{Type: e.Type})
	}
	return out
}

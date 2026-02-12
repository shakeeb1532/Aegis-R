package integration

import (
	"os"
	"path/filepath"
	"testing"

	"aman/internal/testutil"
)

func readFixture(t *testing.T, parts ...string) []byte {
	t.Helper()
	root := testutil.RepoRoot(t)
	path := filepath.Join(append([]string{root}, parts...)...)
	//nolint:gosec // path built from repo root
	// #nosec G304
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return data
}

func TestFixturesECS(t *testing.T) {
	data := readFixture(t, "data", "fixtures", "ecs", "sample.json")
	events, err := IngestEvents(data, IngestOptions{Schema: SchemaECS})
	if err != nil || len(events) == 0 {
		t.Fatalf("ingest ecs: %v", err)
	}
}

func TestFixturesOCSF(t *testing.T) {
	data := readFixture(t, "data", "fixtures", "ocsf", "sample.json")
	events, err := IngestEvents(data, IngestOptions{Schema: SchemaOCSF})
	if err != nil || len(events) == 0 {
		t.Fatalf("ingest ocsf: %v", err)
	}
}

func TestFixturesCIM(t *testing.T) {
	data := readFixture(t, "data", "fixtures", "cim", "sample.json")
	events, err := IngestEvents(data, IngestOptions{Schema: SchemaCIM})
	if err != nil || len(events) == 0 {
		t.Fatalf("ingest cim: %v", err)
	}
}

func TestFixturesMDEDevice(t *testing.T) {
	data := readFixture(t, "data", "fixtures", "mde_device.json")
	events, err := IngestEvents(data, IngestOptions{Schema: SchemaMDE, Kind: "device"})
	if err != nil || len(events) == 0 {
		t.Fatalf("ingest mde device: %v", err)
	}
}

func TestFixturesMDEIdentity(t *testing.T) {
	data := readFixture(t, "data", "fixtures", "mde_identity.json")
	events, err := IngestEvents(data, IngestOptions{Schema: SchemaMDE, Kind: "identity"})
	if err != nil || len(events) == 0 {
		t.Fatalf("ingest mde identity: %v", err)
	}
}

func TestFixturesElasticECS(t *testing.T) {
	data := readFixture(t, "data", "fixtures", "elastic_ecs.json")
	events, err := IngestEvents(data, IngestOptions{Schema: SchemaElasticECS})
	if err != nil || len(events) == 0 {
		t.Fatalf("ingest elastic ecs: %v", err)
	}
}

func TestFixturesSplunkAuth(t *testing.T) {
	data := readFixture(t, "data", "fixtures", "splunk_cim_auth.json")
	events, err := IngestEvents(data, IngestOptions{Schema: SchemaSplunkAuth})
	if err != nil || len(events) == 0 {
		t.Fatalf("ingest splunk auth: %v", err)
	}
}

func TestFixturesSplunkNet(t *testing.T) {
	data := readFixture(t, "data", "fixtures", "splunk_cim_net.json")
	events, err := IngestEvents(data, IngestOptions{Schema: SchemaSplunkNet})
	if err != nil || len(events) == 0 {
		t.Fatalf("ingest splunk net: %v", err)
	}
}

func TestFixturesOktaSystemLog(t *testing.T) {
	data := readFixture(t, "data", "fixtures", "okta_systemlog.json")
	events, err := IngestEvents(data, IngestOptions{Schema: SchemaOkta})
	if err != nil || len(events) == 0 {
		t.Fatalf("ingest okta: %v", err)
	}
}

func TestFixturesCloudTrail(t *testing.T) {
	data := readFixture(t, "data", "fixtures", "aws_cloudtrail.json")
	events, err := IngestEvents(data, IngestOptions{Schema: SchemaCloudTrail})
	if err != nil || len(events) == 0 {
		t.Fatalf("ingest cloudtrail: %v", err)
	}
}

func TestFixturesSentinelCSL(t *testing.T) {
	data := readFixture(t, "data", "fixtures", "sentinel_csl.json")
	events, err := IngestEvents(data, IngestOptions{Schema: SchemaSentinelCSL})
	if err != nil || len(events) == 0 {
		t.Fatalf("ingest sentinel csl: %v", err)
	}
}

func TestFixturesCrowdStrike(t *testing.T) {
	data := readFixture(t, "data", "fixtures", "crowdstrike_fdr.json")
	events, err := IngestEvents(data, IngestOptions{Schema: SchemaCrowdStrike})
	if err != nil || len(events) == 0 {
		t.Fatalf("ingest crowdstrike: %v", err)
	}
}

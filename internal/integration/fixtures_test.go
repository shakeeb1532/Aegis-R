package integration

import (
	"os"
	"testing"
)

func TestFixturesECS(t *testing.T) {
	data, err := os.ReadFile("/Users/shak1532/Downloads/Aegis-R/data/fixtures/ecs/sample.json")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	events, err := IngestEvents(data, IngestOptions{Schema: SchemaECS})
	if err != nil || len(events) == 0 {
		t.Fatalf("ingest ecs: %v", err)
	}
}

func TestFixturesOCSF(t *testing.T) {
	data, err := os.ReadFile("/Users/shak1532/Downloads/Aegis-R/data/fixtures/ocsf/sample.json")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	events, err := IngestEvents(data, IngestOptions{Schema: SchemaOCSF})
	if err != nil || len(events) == 0 {
		t.Fatalf("ingest ocsf: %v", err)
	}
}

func TestFixturesCIM(t *testing.T) {
	data, err := os.ReadFile("/Users/shak1532/Downloads/Aegis-R/data/fixtures/cim/sample.json")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	events, err := IngestEvents(data, IngestOptions{Schema: SchemaCIM})
	if err != nil || len(events) == 0 {
		t.Fatalf("ingest cim: %v", err)
	}
}

func TestFixturesMDEDevice(t *testing.T) {
	data, err := os.ReadFile("/Users/shak1532/Downloads/Aegis-R/data/fixtures/mde_device.json")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	events, err := IngestEvents(data, IngestOptions{Schema: SchemaMDE, Kind: "device"})
	if err != nil || len(events) == 0 {
		t.Fatalf("ingest mde device: %v", err)
	}
}

func TestFixturesMDEIdentity(t *testing.T) {
	data, err := os.ReadFile("/Users/shak1532/Downloads/Aegis-R/data/fixtures/mde_identity.json")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	events, err := IngestEvents(data, IngestOptions{Schema: SchemaMDE, Kind: "identity"})
	if err != nil || len(events) == 0 {
		t.Fatalf("ingest mde identity: %v", err)
	}
}

func TestFixturesElasticECS(t *testing.T) {
	data, err := os.ReadFile("/Users/shak1532/Downloads/Aegis-R/data/fixtures/elastic_ecs.json")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	events, err := IngestEvents(data, IngestOptions{Schema: SchemaElasticECS})
	if err != nil || len(events) == 0 {
		t.Fatalf("ingest elastic ecs: %v", err)
	}
}

func TestFixturesSplunkAuth(t *testing.T) {
	data, err := os.ReadFile("/Users/shak1532/Downloads/Aegis-R/data/fixtures/splunk_cim_auth.json")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	events, err := IngestEvents(data, IngestOptions{Schema: SchemaSplunkAuth})
	if err != nil || len(events) == 0 {
		t.Fatalf("ingest splunk auth: %v", err)
	}
}

func TestFixturesSplunkNet(t *testing.T) {
	data, err := os.ReadFile("/Users/shak1532/Downloads/Aegis-R/data/fixtures/splunk_cim_net.json")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	events, err := IngestEvents(data, IngestOptions{Schema: SchemaSplunkNet})
	if err != nil || len(events) == 0 {
		t.Fatalf("ingest splunk net: %v", err)
	}
}

func TestFixturesOktaSystemLog(t *testing.T) {
	data, err := os.ReadFile("/Users/shak1532/Downloads/Aegis-R/data/fixtures/okta_systemlog.json")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	events, err := IngestEvents(data, IngestOptions{Schema: SchemaOkta})
	if err != nil || len(events) == 0 {
		t.Fatalf("ingest okta: %v", err)
	}
}

func TestFixturesCloudTrail(t *testing.T) {
	data, err := os.ReadFile("/Users/shak1532/Downloads/Aegis-R/data/fixtures/aws_cloudtrail.json")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	events, err := IngestEvents(data, IngestOptions{Schema: SchemaCloudTrail})
	if err != nil || len(events) == 0 {
		t.Fatalf("ingest cloudtrail: %v", err)
	}
}

func TestFixturesSentinelCSL(t *testing.T) {
	data, err := os.ReadFile("/Users/shak1532/Downloads/Aegis-R/data/fixtures/sentinel_csl.json")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	events, err := IngestEvents(data, IngestOptions{Schema: SchemaSentinelCSL})
	if err != nil || len(events) == 0 {
		t.Fatalf("ingest sentinel csl: %v", err)
	}
}

func TestFixturesCrowdStrike(t *testing.T) {
	data, err := os.ReadFile("/Users/shak1532/Downloads/Aegis-R/data/fixtures/crowdstrike_fdr.json")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	events, err := IngestEvents(data, IngestOptions{Schema: SchemaCrowdStrike})
	if err != nil || len(events) == 0 {
		t.Fatalf("ingest crowdstrike: %v", err)
	}
}

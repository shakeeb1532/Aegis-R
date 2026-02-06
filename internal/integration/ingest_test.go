package integration

import (
	"testing"
)

func TestIngestECS(t *testing.T) {
	raw := []byte(`[
  {"@timestamp":"2026-02-05T00:00:00Z","event":{"id":"1","type":["beacon_outbound"]},"host":{"name":"h1"},"user":{"name":"alice"},"labels":{"k":"v"}}
]`)
	events, err := IngestEvents(raw, IngestOptions{Schema: SchemaECS})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if len(events) != 1 || events[0].Type != "beacon_outbound" {
		t.Fatalf("unexpected ecs mapping")
	}
}

func TestIngestOCSF(t *testing.T) {
	raw := []byte(`[
  {"event_uid":"1","type_name":"lsass_access","time":"2026-02-05T00:00:00Z","hostname":"h1","user_name":"alice","attributes":{"k":"v"}}
]`)
	events, err := IngestEvents(raw, IngestOptions{Schema: SchemaOCSF})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if len(events) != 1 || events[0].Type != "lsass_access" {
		t.Fatalf("unexpected ocsf mapping")
	}
}

func TestIngestCIM(t *testing.T) {
	raw := []byte(`[
  {"_time":"2026-02-05 00:00:00","source":"s","user":"alice","host":"h1","action":"network_logon","fields":{"k":"v"}}
]`)
	events, err := IngestEvents(raw, IngestOptions{Schema: SchemaCIM})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if len(events) != 1 || events[0].Type != "network_logon" {
		t.Fatalf("unexpected cim mapping")
	}
}

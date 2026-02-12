package core_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"aman/internal/core"
	"aman/internal/env"
	"aman/internal/integration"
	"aman/internal/logic"
	"aman/internal/model"
	"aman/internal/state"
	"aman/internal/testutil"
)

func TestFixtureThreading(t *testing.T) {
	root := testutil.RepoRoot(t)
	fixtures := []struct {
		Path   string
		Schema integration.Schema
		Kind   string
	}{
		{"data/fixtures/ecs/sample.json", integration.SchemaECS, ""},
		{"data/fixtures/ocsf/sample.json", integration.SchemaOCSF, ""},
		{"data/fixtures/cim/sample.json", integration.SchemaCIM, ""},
		{"data/fixtures/elastic_ecs.json", integration.SchemaElasticECS, ""},
		{"data/fixtures/splunk_cim_auth.json", integration.SchemaSplunkAuth, ""},
		{"data/fixtures/splunk_cim_net.json", integration.SchemaSplunkNet, ""},
		{"data/fixtures/okta_systemlog.json", integration.SchemaOkta, ""},
		{"data/fixtures/aws_cloudtrail.json", integration.SchemaCloudTrail, ""},
		{"data/fixtures/sentinel_csl.json", integration.SchemaSentinelCSL, ""},
		{"data/fixtures/crowdstrike_fdr.json", integration.SchemaCrowdStrike, ""},
		{"data/fixtures/mde_device.json", integration.SchemaMDE, "device"},
		{"data/fixtures/mde_identity.json", integration.SchemaMDE, "identity"},
	}
	all := []model.Event{}
	for _, f := range fixtures {
		data, err := os.ReadFile(filepath.Join(root, f.Path))
		if err != nil {
			t.Fatalf("read fixture %s: %v", f.Path, err)
		}
		events, err := integration.IngestEvents(data, integration.IngestOptions{Schema: f.Schema, Kind: f.Kind})
		if err != nil {
			t.Fatalf("ingest %s: %v", f.Path, err)
		}
		all = append(all, events...)
	}
	if len(all) == 0 {
		t.Fatalf("expected fixture events")
	}
	environment, err := env.Load(filepath.Join(root, "data", "env.json"))
	if err != nil {
		t.Fatalf("env load: %v", err)
	}
	out := core.Assess(all, logic.DefaultRules(), environment, state.New())
	if len(out.State.Threads) < 2 {
		t.Fatalf("expected fixture threads >=2, got %d", len(out.State.Threads))
	}
	hasConf := false
	for _, tinfo := range out.State.Threads {
		if tinfo.Confidence >= 0.7 {
			hasConf = true
		}
	}
	if !hasConf {
		t.Fatalf("expected at least one confident fixture thread")
	}
	_, _ = json.Marshal(out) // ensure json-safe
}

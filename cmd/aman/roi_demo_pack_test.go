package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBuildROIScorecard(t *testing.T) {
	dir := t.TempDir()
	pilot := filepath.Join(dir, "pilot.json")
	integration := filepath.Join(dir, "integration.json")
	bench := filepath.Join(dir, "bench.md")

	pilotBody := `{
  "queue_reduction_pct": 20,
  "escalated_precision_proxy_pct": 80,
  "suppressed_later_true_rate_pct": 0
}`
	intBody := `{"passed":3,"failed":0}`
	benchBody := "Observed overlay overhead: +17.3% wall-clock on this workload.\n"

	if err := os.WriteFile(pilot, []byte(pilotBody), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(integration, []byte(intBody), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bench, []byte(benchBody), 0600); err != nil {
		t.Fatal(err)
	}

	score, err := buildROIScorecard(pilot, integration, bench)
	if err != nil {
		t.Fatalf("build scorecard: %v", err)
	}
	if score.OverlayOverheadPct != 17.3 {
		t.Fatalf("unexpected overhead: %.2f", score.OverlayOverheadPct)
	}
	if score.ReadinessScore <= 0 {
		t.Fatalf("expected readiness score > 0")
	}
	md := renderROIScorecardMarkdown(score)
	if !strings.Contains(md, "Composite readiness score") {
		t.Fatalf("expected scorecard markdown")
	}
}

func TestParseOverlayOverheadPct_WithoutPlusSign(t *testing.T) {
	md := "Observed overlay overhead: 17.3% wall-clock on this workload.\n"
	got := parseOverlayOverheadPct(md)
	if got != 17.3 {
		t.Fatalf("expected 17.3, got %.2f", got)
	}
}

func TestWritePilotMetricsArtifact_ReturnsErrorOnUnreadableSource(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "pilot_source")
	dst := filepath.Join(dir, "pilot_out.json")
	if err := os.Mkdir(src, 0700); err != nil {
		t.Fatal(err)
	}
	err := writePilotMetricsArtifact(src, dst, time.Now().UTC())
	if err == nil {
		t.Fatalf("expected read error for directory source")
	}
}

func TestWritePilotMetricsArtifact_WritesSeedWhenSourceMissing(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "missing_source.json")
	dst := filepath.Join(dir, "pilot_out.json")
	now := time.Date(2026, 2, 22, 10, 0, 0, 0, time.UTC)

	if err := writePilotMetricsArtifact(src, dst, now); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	raw, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read dst: %v", err)
	}
	var out PilotMetrics
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal dst: %v", err)
	}
	if !out.GeneratedAt.Equal(now) {
		t.Fatalf("unexpected generated_at: %s", out.GeneratedAt)
	}
}

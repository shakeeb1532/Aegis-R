package progression

import (
	"strings"
	"testing"
	"time"

	"aman/internal/state"
)

func TestBuildAttackPaths(t *testing.T) {
	now := time.Now().UTC()
	events := []state.ProgressEvent{
		{Time: now, Asset: "host-1", Principal: "alice", Stage: "identity_auth", Action: "impossible_travel", Confidence: 0.72},
		{Time: now.Add(time.Minute), Asset: "host-1", Principal: "alice", Stage: "host_execution", Action: "process_creation", Confidence: 0.84},
	}
	paths := BuildAttackPaths(events)
	if len(paths) != 1 {
		t.Fatalf("expected one path, got %d", len(paths))
	}
	if paths[0].Asset != "host-1" {
		t.Fatalf("unexpected asset: %s", paths[0].Asset)
	}
	if len(paths[0].Stages) != 2 {
		t.Fatalf("expected two stages, got %d", len(paths[0].Stages))
	}
}

func TestRenderMermaid(t *testing.T) {
	paths := []AttackPath{
		{
			ID:        "path:host-1:alice",
			Asset:     "host-1",
			Principal: "alice",
			Stages:    []string{"identity_auth", "host_execution"},
		},
	}
	out := RenderMermaid(paths)
	if !strings.Contains(out, "flowchart LR") {
		t.Fatalf("expected mermaid header")
	}
	if !strings.Contains(out, "identity_auth") {
		t.Fatalf("expected stage in mermaid output")
	}
}

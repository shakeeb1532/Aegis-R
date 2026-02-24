package progression

import (
	"strings"
	"testing"
	"time"

	"aman/internal/env"
	"aman/internal/state"
)

func TestBuildKillChainEdges(t *testing.T) {
	now := time.Now().UTC()
	evs := []state.ProgressEvent{
		{Time: now, Stage: "identity_auth", Confidence: 0.7},
		{Time: now.Add(time.Minute), Stage: "host_execution", Confidence: 0.8},
		{Time: now.Add(2 * time.Minute), Stage: "lateral_network", Confidence: 0.9},
	}
	edges := BuildKillChainEdges(evs)
	if len(edges) != 2 {
		t.Fatalf("expected 2 edges, got %d", len(edges))
	}
}

func TestBuildBlastRadius(t *testing.T) {
	environment := env.Environment{
		Hosts: []env.Host{
			{ID: "h1", Critical: true},
			{ID: "h2", Critical: false},
		},
	}
	st := state.New()
	st.CompromisedHosts["h1"] = true
	st.ReachableHosts["h1"] = true
	st.ReachableHosts["h2"] = true
	br := BuildBlastRadius(environment, st)
	if len(br.CompromisedCritical) != 1 || br.CompromisedCritical[0] != "h1" {
		t.Fatalf("unexpected compromised critical list: %+v", br.CompromisedCritical)
	}
	if br.ReachableTotal != 2 {
		t.Fatalf("expected reachable total 2, got %d", br.ReachableTotal)
	}
}

func TestSuggestControlPoints(t *testing.T) {
	environment := env.Environment{
		TrustBoundaries: []env.TrustBoundary{{ID: "tb1", From: "a", To: "b", Mode: "conditional"}},
	}
	st := state.New()
	st.Progression = []state.ProgressEvent{{Stage: "identity_auth"}, {Stage: "lateral_network"}}
	cps := SuggestControlPoints(environment, st)
	if len(cps) < 2 {
		t.Fatalf("expected at least 2 control points, got %d", len(cps))
	}
}

func TestBuildIdentityPivots(t *testing.T) {
	now := time.Now().UTC()
	evs := []state.ProgressEvent{
		{Time: now, Principal: "alice", Asset: "h1", Action: "login", Confidence: 0.7},
		{Time: now.Add(time.Minute), Principal: "bob", Asset: "h1", Action: "role_change", Confidence: 0.8},
	}
	pivots := BuildIdentityPivots(evs)
	if len(pivots) == 0 {
		t.Fatalf("expected pivots")
	}
}

func TestBuildTimeLapse(t *testing.T) {
	now := time.Now().UTC()
	evs := []state.ProgressEvent{
		{Time: now, Principal: "alice", Asset: "h1", Stage: "identity_auth"},
		{Time: now.Add(2 * time.Minute), Principal: "bob", Asset: "h2", Stage: "host_execution"},
	}
	slices := BuildTimeLapse(evs, 5*time.Minute)
	if len(slices) != 1 {
		t.Fatalf("expected 1 slice, got %d", len(slices))
	}
}

func TestBuildEvidenceConfidenceEdges(t *testing.T) {
	now := time.Now().UTC()
	evs := []state.ProgressEvent{
		{Time: now, Stage: "identity_auth", Confidence: 0.3},
		{Time: now.Add(time.Minute), Stage: "host_execution", Confidence: 0.4},
	}
	edges := BuildEvidenceConfidenceEdges(evs)
	if len(edges) != 1 {
		t.Fatalf("expected 1 edge, got %d", len(edges))
	}
	if !edges[0].LowConfidence {
		t.Fatalf("expected low confidence edge")
	}
	m := RenderConfidenceMermaid(edges)
	if !strings.Contains(m, "flowchart LR") {
		t.Fatalf("expected mermaid output")
	}
}

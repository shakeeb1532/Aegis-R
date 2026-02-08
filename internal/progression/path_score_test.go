package progression

import (
	"testing"
	"time"

	"aegisr/internal/state"
)

func TestBuildPathScores(t *testing.T) {
	now := time.Date(2026, 2, 8, 12, 0, 0, 0, time.UTC)
	events := []state.ProgressEvent{
		{Time: now.Add(-10 * time.Minute), Stage: "identity_auth", Confidence: 0.8},
		{Time: now.Add(-30 * time.Minute), Stage: "host_execution", Confidence: 0.7},
		{Time: now.Add(-90 * time.Minute), Stage: "lateral_network", Confidence: 0.6},
	}
	scores, overall := BuildPathScores(events, now)
	if len(scores) == 0 {
		t.Fatalf("expected scores")
	}
	if overall <= 0 {
		t.Fatalf("expected overall score > 0")
	}
}

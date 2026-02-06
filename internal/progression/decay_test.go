package progression

import (
	"testing"
	"time"

	"aegisr/internal/state"
)

type peWrap struct{ *state.ProgressEvent }

func TestApplyDecayWindow(t *testing.T) {
	now := time.Now().UTC()
	old := state.ProgressEvent{Time: now.Add(-48 * time.Hour), Confidence: 1}
	recent := state.ProgressEvent{Time: now.Add(-2 * time.Hour), Confidence: 1}
	events := []ProgressEventLike{&old, &recent}
	out := ApplyDecay(events, now, 24*time.Hour)
	if len(out) != 1 {
		t.Fatalf("expected 1 event, got %d", len(out))
	}
	if out[0].GetConfidence() >= 1.0 {
		t.Fatalf("expected decayed confidence")
	}
}

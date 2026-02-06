package progression

import (
	"testing"
	"time"

	"aegisr/internal/env"
	"aegisr/internal/state"
)

func TestOverlayGraph(t *testing.T) {
	environment := env.Environment{Hosts: []env.Host{{ID: "h1", Zone: "a"}}}
	st := state.New()
	st.Position.Assets = []string{"h1"}
	OverlayGraph(environment, &st)
	if len(st.GraphOverlay.CurrentNodes) == 0 {
		t.Fatalf("expected current nodes")
	}
	if len(st.GraphOverlay.Reachable) == 0 {
		t.Fatalf("expected reachable nodes")
	}
	_ = time.Now()
}

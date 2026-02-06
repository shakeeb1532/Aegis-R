package progression

import (
	"testing"
	"time"

	"aegisr/internal/env"
	"aegisr/internal/model"
	"aegisr/internal/state"
)

func TestProgressionUpdate(t *testing.T) {
	env := env.Environment{Hosts: []env.Host{{ID: "h1", Zone: "user-net", Critical: true}}}
	events := []model.Event{{ID: "e1", Time: time.Now().UTC(), Host: "h1", User: "alice", Type: "process_creation"}}
	st := state.New()
	envps := Normalize(events, env)
	Update(envps, &st)
	if len(st.Progression) == 0 {
		t.Fatalf("expected progression")
	}
	if st.Position.Stage == "" {
		t.Fatalf("expected position stage")
	}
}

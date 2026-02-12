package core

import (
	"testing"
	"time"

	"aman/internal/env"
	"aman/internal/logic"
	"aman/internal/model"
	"aman/internal/state"
)

func TestAssessProducesNextMoves(t *testing.T) {
	environment := env.Environment{
		Hosts: []env.Host{
			{ID: "host-1", Zone: "user-net", Critical: false},
			{ID: "host-2", Zone: "server-net", Critical: true},
		},
		Identities: []env.Identity{
			{ID: "svc-admin", PrivLevel: "high"},
		},
		TrustBoundaries: []env.TrustBoundary{
			{ID: "tb-1", From: "user-net", To: "server-net", Mode: "allow"},
		},
	}

	events := []model.Event{
		{ID: "1", Time: time.Now(), Host: "host-1", Type: "beacon_outbound"},
	}

	out := Assess(events, logic.DefaultRules(), environment, state.New())
	if len(out.NextMoves) == 0 {
		t.Fatalf("expected next moves")
	}
}

package core

import (
	"testing"
	"time"

	"aegisr/internal/env"
	"aegisr/internal/logic"
	"aegisr/internal/model"
	"aegisr/internal/state"
)

func TestAssessDriftSignals(t *testing.T) {
	environment := env.Environment{}
	events := []model.Event{
		{ID: "1", Time: time.Now(), Type: "trust_boundary_change"},
		{ID: "2", Time: time.Now(), Type: "new_admin_account"},
	}
	out := Assess(events, logic.DefaultRules(), environment, state.New())
	if len(out.DriftSignals) < 2 {
		t.Fatalf("expected drift signals")
	}
}

package eval

import (
	"testing"
	"time"

	aenv "aman/internal/env"
	"aman/internal/logic"
	"aman/internal/model"
)

func TestClassifyTreatsPrecondMissingAsIncomplete(t *testing.T) {
	r := model.RuleResult{
		Feasible:   false,
		PrecondOK:  false,
		ReasonCode: "precond_missing",
		MissingEvidence: []model.EvidenceRequirement{
			{Type: "precond:initial_access", Description: "missing"},
		},
	}
	if got := classify(r); got != OutcomeIncomplete {
		t.Fatalf("expected incomplete, got %s", got)
	}
}

func TestScoreUsesScenarioEnvironmentWhenProvided(t *testing.T) {
	requiresReachability := true
	rules := []logic.Rule{
		{
			ID:   "TA0008.ADMIN_PROTOCOL_LATERAL",
			Name: "Admin Protocol Lateral Movement",
			Requirements: []model.EvidenceRequirement{
				{Type: "new_inbound_admin_protocol", Description: "admin protocol"},
				{Type: "network_logon", Description: "network logon"},
			},
			Preconds:             []string{"credential_access"},
			RequiresContext:      "host",
			RequiresReachability: &requiresReachability,
			TargetEventTypes:     []string{"new_inbound_admin_protocol"},
		},
	}
	scenarios := ScenariosFile{
		Scenarios: []Scenario{
			{
				ID: "env-aware",
				Events: []model.Event{
					{ID: "e1", Time: time.Date(2026, 3, 14, 10, 0, 0, 0, time.UTC), Host: "host-a", User: "alice", Type: "lsass_access"},
					{ID: "e2", Time: time.Date(2026, 3, 14, 10, 1, 0, 0, time.UTC), Host: "host-a", User: "alice", Type: "network_logon"},
					{ID: "e3", Time: time.Date(2026, 3, 14, 10, 1, 30, 0, time.UTC), Host: "host-a", User: "alice", Type: "new_inbound_admin_protocol"},
				},
				Environment: aenv.Environment{
					Hosts: []aenv.Host{{ID: "host-a", Zone: "corp"}},
				},
				Labels: []Label{{RuleID: "TA0008.ADMIN_PROTOCOL_LATERAL", Outcome: OutcomeFeasible}},
			},
		},
	}
	rep := Score(scenarios, rules)
	if rep.Total != 1 || rep.Accuracy != 1 {
		t.Fatalf("expected env-aware score success, got total=%d accuracy=%f mismatches=%v", rep.Total, rep.Accuracy, rep.Mismatches)
	}
}

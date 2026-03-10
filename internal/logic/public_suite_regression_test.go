package logic

import (
	"testing"
	"time"

	"aman/internal/model"
)

func TestCredentialAccessDerivedFromCredentialToolExecution(t *testing.T) {
	events := []model.Event{
		{
			ID:   "e1",
			Time: time.Date(2026, 2, 6, 9, 39, 40, 0, time.UTC),
			Host: "host-2",
			User: "alice",
			Type: "process_creation",
			Details: map[string]interface{}{
				"tool": "mimikatz",
			},
		},
	}
	index := map[string][]int{"process_creation": {0}}
	facts := deriveCausalFacts(events, index)
	f, ok := facts["credential_access"]
	if !ok || !f.Observed {
		t.Fatalf("expected credential_access to be derived from credential tooling")
	}
}

func TestIdentityCompromiseNotSatisfiedByMFABypassRuleEvidenceAlone(t *testing.T) {
	events := []model.Event{
		{ID: "e1", Time: time.Date(2026, 2, 6, 13, 0, 0, 0, time.UTC), Host: "idp-1", User: "alice", Type: "mfa_method_removed"},
		{ID: "e2", Time: time.Date(2026, 2, 6, 13, 0, 5, 0, time.UTC), Host: "idp-1", User: "alice", Type: "token_refresh_anomaly"},
	}
	index := map[string][]int{
		"mfa_method_removed":    {0},
		"token_refresh_anomaly": {1},
	}
	facts := deriveCausalFacts(events, index)
	if f, ok := facts["identity_compromise"]; ok && f.Observed {
		t.Fatalf("expected identity_compromise to remain unset for MFA-bypass evidence alone")
	}
}

func TestReasonCodeUsesPrecondMissingWhenOnlyPreconditionsAreMissing(t *testing.T) {
	missing := []model.EvidenceRequirement{
		{Type: "precond:initial_access", Description: "Precondition not observed"},
	}
	if got := reasonCode(false, missing, 3); got != "precond_missing" {
		t.Fatalf("expected precond_missing, got %q", got)
	}
}

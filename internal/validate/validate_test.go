package validate

import (
	"testing"

	"aman/internal/env"
	"aman/internal/governance"
	"aman/internal/logic"
	"aman/internal/model"
)

func TestEnvironmentValidation(t *testing.T) {
	e := env.Environment{}
	if err := Environment(e); err == nil {
		t.Fatalf("expected validation error")
	}
}

func TestPolicyValidation(t *testing.T) {
	p := governance.Policy{ID: "p", MinApprovals: 1, AllowedSignerRoles: []string{"approver"}}
	if err := Policy(p); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRulesValidation(t *testing.T) {
	r := []logic.Rule{{ID: "r1", Name: "n", Requirements: []model.EvidenceRequirement{{Type: "e1", Description: "d"}}}}
	if err := Rules(r); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

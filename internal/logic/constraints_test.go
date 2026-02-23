package logic

import (
	"strings"
	"testing"

	"aman/internal/governance"
	"aman/internal/model"
)

func TestApplyConstraintsForbidEvidence(t *testing.T) {
	rep := model.ReasoningReport{
		Results: []model.RuleResult{
			{
				RuleID:           "R1",
				Feasible:         true,
				SupportingEventIDs: []string{"ev-1", "ev-2"},
				Explanation:      "base",
			},
		},
	}
	constraints := []governance.ReasoningConstraint{
		{
			RuleID:         "R1",
			ForbidEvidence: []string{"ev-2"},
		},
	}
	ApplyConstraints(&rep, constraints)
	r := rep.Results[0]
	if r.Feasible {
		t.Fatalf("expected feasible=false when forbidden evidence is present")
	}
	if r.ReasonCode != "policy_override" {
		t.Fatalf("expected policy_override, got %q", r.ReasonCode)
	}
	if !strings.Contains(r.Explanation, "Forbidden evidence present") {
		t.Fatalf("expected forbidden evidence message in explanation")
	}
}

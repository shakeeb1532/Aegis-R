package eval

import (
	"testing"

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

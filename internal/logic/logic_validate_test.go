package logic

import (
	"testing"

	"aegisr/internal/model"
)

func TestValidateRules(t *testing.T) {
	rules := []Rule{{ID: "X", Name: "Test", Requirements: []model.EvidenceRequirement{{Type: "e1", Description: "d"}}}}
	if err := ValidateRules(rules); err != nil {
		t.Fatalf("expected valid rules: %v", err)
	}
}

func TestValidateRulesDuplicate(t *testing.T) {
	rules := []Rule{
		{ID: "X", Name: "Test", Requirements: []model.EvidenceRequirement{{Type: "e1", Description: "d"}}},
		{ID: "X", Name: "Test2", Requirements: []model.EvidenceRequirement{{Type: "e2", Description: "d"}}},
	}
	if err := ValidateRules(rules); err == nil {
		t.Fatalf("expected duplicate id error")
	}
}

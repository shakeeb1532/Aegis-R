package logic

import (
	"testing"

	"aman/internal/model"
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

func TestValidateRulesInvalidRequiresContext(t *testing.T) {
	rules := []Rule{
		{
			ID:              "X",
			Name:            "Test",
			RequiresContext: "network",
			Requirements:    []model.EvidenceRequirement{{Type: "e1", Description: "d"}},
		},
	}
	if err := ValidateRules(rules); err == nil {
		t.Fatalf("expected invalid requires_context error")
	}
}

func TestDefaultRulesMitreMetadataNormalized(t *testing.T) {
	rules := DefaultRules()
	if len(rules) == 0 {
		t.Fatalf("expected default rules")
	}
	for _, r := range rules {
		if r.Mitre.Tactic == "" || r.Mitre.Technique == "" {
			t.Fatalf("expected MITRE metadata for %s", r.ID)
		}
	}
}

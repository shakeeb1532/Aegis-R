package logic

import (
	"strings"
	"testing"

	"aman/internal/model"
)

func TestDefaultRulesDoNotDependOnLegacyBehaviorFallback(t *testing.T) {
	rules := DefaultRules()
	if len(rules) == 0 {
		t.Fatalf("expected default rules")
	}
	for _, r := range rules {
		if deps := legacyBehaviorDependencies(r); len(deps) > 0 {
			t.Fatalf("rule %s still depends on legacy fallback: %s", r.ID, strings.Join(deps, ", "))
		}
	}
}

func TestLintRulesWarnsOnLegacyBehaviorFallback(t *testing.T) {
	rules := []Rule{
		{
			ID:           "TA0010.EXFIL",
			Name:         "Exfil test",
			Explain:      "test",
			Requirements: []model.EvidenceRequirement{{Type: "large_outbound_transfer", Description: "d"}},
		},
	}
	warnings := LintRules(rules)
	for _, w := range warnings {
		if w.Issue == "legacy_behavior_fallback" {
			return
		}
	}
	t.Fatalf("expected legacy_behavior_fallback warning")
}

func TestRuleBehaviorCoverageReportCountsExplicitBehavior(t *testing.T) {
	rules := []Rule{
		{
			ID:                   "A",
			Name:                 "A",
			Explain:              "test",
			Requirements:         []model.EvidenceRequirement{{Type: "e1", Description: "d"}},
			Contradictions:       []string{"x"},
			RequiresContext:      "host",
			RequiresReachability: boolPtr(true),
			RequiresHighPriv:     boolPtr(true),
			TargetEventTypes:     []string{"e1"},
		},
		{
			ID:           "B",
			Name:         "B",
			Explain:      "test",
			Requirements: []model.EvidenceRequirement{{Type: "e2", Description: "d"}},
		},
	}
	got := RuleBehaviorCoverageReport(rules)
	if got.TotalRules != 2 || got.ExplicitContradictions != 1 || got.ExplicitContext != 1 ||
		got.ExplicitReachability != 1 || got.ExplicitHighPriv != 1 || got.ExplicitTargetEventTypes != 1 ||
		got.RulesWithoutLegacyFallback != 2 {
		t.Fatalf("unexpected coverage: %+v", got)
	}
}

func boolPtr(v bool) *bool { return &v }

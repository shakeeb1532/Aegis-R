package logic

import (
	"sort"
	"strings"
)

type RuleBehaviorCoverage struct {
	TotalRules                 int `json:"total_rules"`
	ExplicitContradictions     int `json:"explicit_contradictions"`
	ExplicitContext            int `json:"explicit_context"`
	ExplicitReachability       int `json:"explicit_reachability"`
	ExplicitHighPriv           int `json:"explicit_high_priv"`
	ExplicitTargetEventTypes   int `json:"explicit_target_event_types"`
	LegacyFallbackRules        int `json:"legacy_fallback_rules"`
	RulesWithoutLegacyFallback int `json:"rules_without_legacy_fallback"`
}

type RuleLintWarning struct {
	RuleID   string `json:"rule_id"`
	Issue    string `json:"issue"`
	Detail   string `json:"detail,omitempty"`
	Severity string `json:"severity"`
}

var legacyIdentityTypes = map[string]string{
	"valid_account_login": "use signin_success",
	"mfa_disabled":        "use mfa_method_removed or mfa_policy_changed",
}

func ruleBehaviorCoverage(rules []Rule) RuleBehaviorCoverage {
	c := RuleBehaviorCoverage{TotalRules: len(rules)}
	for _, r := range rules {
		if len(r.Contradictions) > 0 {
			c.ExplicitContradictions++
		}
		if strings.TrimSpace(r.RequiresContext) != "" {
			c.ExplicitContext++
		}
		if r.RequiresReachability != nil {
			c.ExplicitReachability++
		}
		if r.RequiresHighPriv != nil {
			c.ExplicitHighPriv++
		}
		if len(r.TargetEventTypes) > 0 {
			c.ExplicitTargetEventTypes++
		}
		if len(legacyBehaviorDependencies(r)) > 0 {
			c.LegacyFallbackRules++
		} else {
			c.RulesWithoutLegacyFallback++
		}
	}
	return c
}

func RuleBehaviorCoverageReport(rules []Rule) RuleBehaviorCoverage {
	return ruleBehaviorCoverage(rules)
}

func legacyBehaviorDependencies(r Rule) []string {
	deps := make([]string, 0, 5)
	if len(legacyContradictions[r.ID]) > 0 && len(r.Contradictions) == 0 {
		deps = append(deps, "contradictions")
	}
	if legacyContextByRule[r.ID] != "" && strings.TrimSpace(r.RequiresContext) == "" {
		deps = append(deps, "requires_context")
	}
	if legacyReachabilityByRule[r.ID] && r.RequiresReachability == nil {
		deps = append(deps, "requires_reachability")
	}
	if legacyHighPrivByRule[r.ID] && r.RequiresHighPriv == nil {
		deps = append(deps, "requires_high_priv")
	}
	if len(legacyTargetEventTypesByRule[r.ID]) > 0 && len(r.TargetEventTypes) == 0 {
		deps = append(deps, "target_event_types")
	}
	sort.Strings(deps)
	return deps
}

func LintRules(rules []Rule) []RuleLintWarning {
	warnings := make([]RuleLintWarning, 0)
	for _, r := range rules {
		if strings.TrimSpace(r.Explain) == "" {
			warnings = append(warnings, RuleLintWarning{
				RuleID:   r.ID,
				Issue:    "missing_explain",
				Detail:   "explain field is empty",
				Severity: "warning",
			})
		}
		if strings.TrimSpace(r.Mitre.Tactic) == "" || strings.TrimSpace(r.Mitre.Technique) == "" {
			warnings = append(warnings, RuleLintWarning{
				RuleID:   r.ID,
				Issue:    "missing_mitre",
				Detail:   "tactic or technique is missing",
				Severity: "warning",
			})
		}

		legacy := []string{}
		for _, req := range r.Requirements {
			if hint, ok := legacyIdentityTypes[req.Type]; ok {
				legacy = append(legacy, req.Type+" ("+hint+")")
			}
		}
		for _, p := range r.Preconds {
			if hint, ok := legacyIdentityTypes[p]; ok {
				legacy = append(legacy, p+" ("+hint+")")
			}
		}
		if len(legacy) > 0 {
			sort.Strings(legacy)
			warnings = append(warnings, RuleLintWarning{
				RuleID:   r.ID,
				Issue:    "legacy_identity_evidence",
				Detail:   strings.Join(legacy, ", "),
				Severity: "warning",
			})
		}
		if deps := legacyBehaviorDependencies(r); len(deps) > 0 {
			warnings = append(warnings, RuleLintWarning{
				RuleID:   r.ID,
				Issue:    "legacy_behavior_fallback",
				Detail:   strings.Join(deps, ", "),
				Severity: "warning",
			})
		}
		if r.RequiresReachability != nil && *r.RequiresReachability && len(r.TargetEventTypes) == 0 {
			warnings = append(warnings, RuleLintWarning{
				RuleID:   r.ID,
				Issue:    "missing_target_event_types",
				Detail:   "reachability-aware rule should declare target_event_types",
				Severity: "warning",
			})
		}
		if len(r.Contradictions) > 0 && strings.TrimSpace(r.RequiresContext) == "" &&
			(strings.Contains(r.ID, "VALID_ACCOUNTS") || strings.Contains(r.ID, "IDENTITY") || strings.Contains(r.ID, "MFA_") || strings.Contains(r.ID, "ACCOUNT_")) {
			warnings = append(warnings, RuleLintWarning{
				RuleID:   r.ID,
				Issue:    "missing_scope_context",
				Detail:   "identity-oriented rule has contradictions but no explicit requires_context",
				Severity: "warning",
			})
		}
	}
	sort.Slice(warnings, func(i, j int) bool {
		if warnings[i].RuleID == warnings[j].RuleID {
			return warnings[i].Issue < warnings[j].Issue
		}
		return warnings[i].RuleID < warnings[j].RuleID
	})
	return warnings
}

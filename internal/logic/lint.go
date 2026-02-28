package logic

import (
	"sort"
	"strings"
)

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
	}
	sort.Slice(warnings, func(i, j int) bool {
		if warnings[i].RuleID == warnings[j].RuleID {
			return warnings[i].Issue < warnings[j].Issue
		}
		return warnings[i].RuleID < warnings[j].RuleID
	})
	return warnings
}

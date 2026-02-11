package logic

import (
	"sort"
	"time"
)

type NistCoverageReport struct {
	GeneratedAt      time.Time           `json:"generated_at"`
	TotalRules       int                 `json:"total_rules"`
	RulesMissingMeta []string            `json:"rules_missing_nist"`
	Categories       []FrameworkCoverage `json:"categories"`
}

type KillChainCoverageReport struct {
	GeneratedAt      time.Time           `json:"generated_at"`
	TotalRules       int                 `json:"total_rules"`
	RulesMissingMeta []string            `json:"rules_missing_kill_chain"`
	Phases           []FrameworkCoverage `json:"phases"`
}

type FrameworkCoverage struct {
	Name      string   `json:"name"`
	RuleCount int      `json:"rule_count"`
	RuleIDs   []string `json:"rule_ids"`
}

func BuildNistCoverage(rules []Rule) NistCoverageReport {
	missing := []string{}
	agg := map[string]map[string]bool{}
	for _, r := range rules {
		if len(r.NistCSF) == 0 {
			missing = append(missing, r.ID)
			continue
		}
		for _, c := range r.NistCSF {
			if c == "" {
				continue
			}
			if _, ok := agg[c]; !ok {
				agg[c] = map[string]bool{}
			}
			agg[c][r.ID] = true
		}
	}
	cats := buildFrameworkCoverage(agg)
	sort.Strings(missing)
	return NistCoverageReport{
		GeneratedAt:      time.Now().UTC(),
		TotalRules:       len(rules),
		RulesMissingMeta: missing,
		Categories:       cats,
	}
}

func BuildKillChainCoverage(rules []Rule) KillChainCoverageReport {
	missing := []string{}
	agg := map[string]map[string]bool{}
	for _, r := range rules {
		if len(r.KillChain) == 0 {
			missing = append(missing, r.ID)
			continue
		}
		for _, p := range r.KillChain {
			if p == "" {
				continue
			}
			if _, ok := agg[p]; !ok {
				agg[p] = map[string]bool{}
			}
			agg[p][r.ID] = true
		}
	}
	phases := buildFrameworkCoverage(agg)
	sort.Strings(missing)
	return KillChainCoverageReport{
		GeneratedAt:      time.Now().UTC(),
		TotalRules:       len(rules),
		RulesMissingMeta: missing,
		Phases:           phases,
	}
}

func buildFrameworkCoverage(agg map[string]map[string]bool) []FrameworkCoverage {
	out := []FrameworkCoverage{}
	for name, ids := range agg {
		list := make([]string, 0, len(ids))
		for id := range ids {
			list = append(list, id)
		}
		sort.Strings(list)
		out = append(out, FrameworkCoverage{
			Name:      name,
			RuleCount: len(list),
			RuleIDs:   list,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].RuleCount == out[j].RuleCount {
			return out[i].Name < out[j].Name
		}
		return out[i].RuleCount > out[j].RuleCount
	})
	return out
}

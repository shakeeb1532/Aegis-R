package logic

import (
	"sort"
	"time"
)

type MitreCoverageReport struct {
	GeneratedAt      time.Time             `json:"generated_at"`
	TotalRules       int                   `json:"total_rules"`
	RulesWithMitre   int                   `json:"rules_with_mitre"`
	RulesMissingMeta []string              `json:"rules_missing_mitre"`
	Tactics          []MitreTacticCoverage `json:"tactics"`
}

type MitreTacticCoverage struct {
	Tactic     string                   `json:"tactic"`
	RuleCount  int                      `json:"rule_count"`
	Techniques []MitreTechniqueCoverage `json:"techniques"`
}

type MitreTechniqueCoverage struct {
	Technique     string   `json:"technique"`
	RuleCount     int      `json:"rule_count"`
	Subtechniques []string `json:"subtechniques"`
	RuleIDs       []string `json:"rule_ids"`
}

func BuildMitreCoverage(rules []Rule) MitreCoverageReport {
	missing := []string{}
	type techAgg struct {
		ruleIDs       map[string]bool
		subtechniques map[string]bool
	}
	tacticAgg := map[string]map[string]*techAgg{}
	withMitre := 0
	for _, r := range rules {
		if r.Mitre.Tactic == "" || r.Mitre.Technique == "" {
			missing = append(missing, r.ID)
			continue
		}
		withMitre++
		if _, ok := tacticAgg[r.Mitre.Tactic]; !ok {
			tacticAgg[r.Mitre.Tactic] = map[string]*techAgg{}
		}
		if _, ok := tacticAgg[r.Mitre.Tactic][r.Mitre.Technique]; !ok {
			tacticAgg[r.Mitre.Tactic][r.Mitre.Technique] = &techAgg{
				ruleIDs:       map[string]bool{},
				subtechniques: map[string]bool{},
			}
		}
		entry := tacticAgg[r.Mitre.Tactic][r.Mitre.Technique]
		if r.ID != "" {
			entry.ruleIDs[r.ID] = true
		}
		if r.Mitre.Subtech != "" {
			entry.subtechniques[r.Mitre.Subtech] = true
		}
	}

	tactics := make([]MitreTacticCoverage, 0, len(tacticAgg))
	for tactic, techniques := range tacticAgg {
		techList := make([]MitreTechniqueCoverage, 0, len(techniques))
		ruleCount := 0
		for tech, agg := range techniques {
			subtechs := keysSorted(agg.subtechniques)
			ruleIDs := keysSorted(agg.ruleIDs)
			techList = append(techList, MitreTechniqueCoverage{
				Technique:     tech,
				RuleCount:     len(ruleIDs),
				Subtechniques: subtechs,
				RuleIDs:       ruleIDs,
			})
			ruleCount += len(ruleIDs)
		}
		sort.Slice(techList, func(i, j int) bool {
			if techList[i].Technique == techList[j].Technique {
				return techList[i].RuleCount > techList[j].RuleCount
			}
			return techList[i].Technique < techList[j].Technique
		})
		tactics = append(tactics, MitreTacticCoverage{
			Tactic:     tactic,
			RuleCount:  ruleCount,
			Techniques: techList,
		})
	}
	sort.Slice(tactics, func(i, j int) bool {
		if tactics[i].Tactic == tactics[j].Tactic {
			return tactics[i].RuleCount > tactics[j].RuleCount
		}
		return tactics[i].Tactic < tactics[j].Tactic
	})
	sort.Strings(missing)

	return MitreCoverageReport{
		GeneratedAt:      time.Now().UTC(),
		TotalRules:       len(rules),
		RulesWithMitre:   withMitre,
		RulesMissingMeta: missing,
		Tactics:          tactics,
	}
}

func keysSorted(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

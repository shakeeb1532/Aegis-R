package assist

import (
	"sort"
	"strings"

	"aegisr/internal/model"
)

type RankConfig struct {
	Categories []string
}

func RankFeasible(rep *model.ReasoningReport, history HistoryFile, cfg RankConfig) {
	allowed := map[string]bool{}
	for _, c := range cfg.Categories {
		allowed[strings.ToLower(strings.TrimSpace(c))] = true
	}
	for i := range rep.Results {
		r := &rep.Results[i]
		if !r.Feasible {
			continue
		}
		base := baseScore(*r)
		adj := 0.0
		if allowed[ruleCategory(r.RuleID)] {
			adj = historyAdjustment(r.RuleID, history)
			r.LikelihoodSource = "hybrid"
		} else {
			r.LikelihoodSource = "deterministic"
		}
		r.LikelihoodScore = clamp(base+adj, 0, 1)
	}
}

func baseScore(r model.RuleResult) float64 {
	evidence := float64(len(r.SupportingEventIDs))
	evidenceScore := 0.0
	if evidence > 0 {
		if evidence >= 4 {
			evidenceScore = 1.0
		} else {
			evidenceScore = evidence / 4.0
		}
	}
	precond := 0.0
	if r.PrecondOK {
		precond = 1.0
	}
	return 0.6*r.Confidence + 0.25*evidenceScore + 0.15*precond
}

func historyAdjustment(ruleID string, history HistoryFile) float64 {
	confirmed := 0
	negative := 0
	for _, inc := range history.Incidents {
		if !contains(inc.RuleIDs, ruleID) && inc.RuleID != ruleID {
			continue
		}
		switch strings.ToLower(inc.Outcome) {
		case "confirmed", "true_positive":
			confirmed++
		case "false_positive", "benign":
			negative++
		}
	}
	total := confirmed + negative
	if total == 0 {
		return 0
	}
	rate := float64(confirmed) / float64(total)
	return (rate - 0.5) * 0.2
}

func ruleCategory(ruleID string) string {
	switch {
	case strings.HasPrefix(ruleID, "TA0006."):
		return "identity"
	case strings.HasPrefix(ruleID, "TA0008.CLOUD"):
		return "cloud"
	case strings.HasPrefix(ruleID, "TA0005.") && strings.Contains(ruleID, "CLOUD"):
		return "cloud"
	default:
		return "other"
	}
}

func SortFeasibleByLikelihood(results []model.RuleResult) []model.RuleResult {
	out := []model.RuleResult{}
	for _, r := range results {
		if r.Feasible {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].LikelihoodScore == out[j].LikelihoodScore {
			return out[i].RuleID < out[j].RuleID
		}
		return out[i].LikelihoodScore > out[j].LikelihoodScore
	})
	return out
}

func clamp(val, min, max float64) float64 {
	if val < min {
		return min
	}
	if val > max {
		return max
	}
	return val
}

func contains(list []string, item string) bool {
	for _, v := range list {
		if v == item {
			return true
		}
	}
	return false
}

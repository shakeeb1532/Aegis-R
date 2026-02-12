package assist

import (
	"sort"
	"strings"

	"aman/internal/model"
)

type SimilarConfig struct {
	Limit         int
	PlaybookLimit int
}

func SuggestSimilar(rep *model.ReasoningReport, history HistoryFile, cfg SimilarConfig) ([]model.SimilarIncident, []string) {
	currentRules := map[string]bool{}
	for _, r := range rep.Results {
		if r.Feasible {
			currentRules[r.RuleID] = true
		}
	}
	type scored struct {
		Inc   HistoryEntry
		Score float64
	}
	scoredList := []scored{}
	for _, inc := range history.Incidents {
		score := similarityScore(inc, currentRules)
		if score == 0 {
			continue
		}
		scoredList = append(scoredList, scored{Inc: inc, Score: score})
	}
	sort.Slice(scoredList, func(i, j int) bool {
		if scoredList[i].Score == scoredList[j].Score {
			return scoredList[i].Inc.ID < scoredList[j].Inc.ID
		}
		return scoredList[i].Score > scoredList[j].Score
	})
	limit := cfg.Limit
	if limit <= 0 {
		limit = 3
	}
	if limit > len(scoredList) {
		limit = len(scoredList)
	}
	out := []model.SimilarIncident{}
	playbooks := []string{}
	seenPlaybook := map[string]bool{}
	for i := 0; i < limit; i++ {
		inc := scoredList[i].Inc
		out = append(out, model.SimilarIncident{
			ID:       inc.ID,
			Summary:  inc.Summary,
			RuleIDs:  dedupeRules(inc),
			Score:    scoredList[i].Score,
			Playbook: inc.Playbook,
		})
		if inc.Playbook != "" && !seenPlaybook[inc.Playbook] {
			playbooks = append(playbooks, inc.Playbook)
			seenPlaybook[inc.Playbook] = true
		}
		if cfg.PlaybookLimit > 0 && len(playbooks) >= cfg.PlaybookLimit {
			break
		}
	}
	return out, playbooks
}

func similarityScore(inc HistoryEntry, currentRules map[string]bool) float64 {
	rules := dedupeRules(inc)
	if len(rules) == 0 {
		return 0
	}
	overlap := 0
	for _, r := range rules {
		if currentRules[r] {
			overlap++
		}
	}
	if overlap == 0 {
		return 0
	}
	return float64(overlap) / float64(len(rules))
}

func dedupeRules(inc HistoryEntry) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, r := range inc.RuleIDs {
		r = strings.TrimSpace(r)
		if r == "" || seen[r] {
			continue
		}
		seen[r] = true
		out = append(out, r)
	}
	if inc.RuleID != "" && !seen[inc.RuleID] {
		out = append(out, inc.RuleID)
	}
	sort.Strings(out)
	return out
}

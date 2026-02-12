package assist

import (
	"testing"

	"aman/internal/model"
)

func TestRankFeasibleHybrid(t *testing.T) {
	rep := model.ReasoningReport{
		Results: []model.RuleResult{
			{RuleID: "TA0006.IDENTITY_ANOMALY", Feasible: true, Confidence: 0.8, PrecondOK: true, SupportingEventIDs: []string{"e1", "e2"}},
			{RuleID: "TA0008.LATERAL", Feasible: true, Confidence: 0.7, PrecondOK: true, SupportingEventIDs: []string{"e3"}},
		},
	}
	hist := HistoryFile{
		Incidents: []HistoryEntry{
			{RuleID: "TA0006.IDENTITY_ANOMALY", Outcome: "confirmed"},
			{RuleID: "TA0006.IDENTITY_ANOMALY", Outcome: "false_positive"},
			{RuleID: "TA0008.LATERAL", Outcome: "confirmed"},
		},
	}
	RankFeasible(&rep, hist, RankConfig{Categories: []string{"identity"}})
	for _, r := range rep.Results {
		if r.Feasible && r.LikelihoodScore == 0 {
			t.Fatalf("expected likelihood score for %s", r.RuleID)
		}
	}
}

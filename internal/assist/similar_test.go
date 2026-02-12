package assist

import (
	"testing"

	"aman/internal/model"
)

func TestSuggestSimilar(t *testing.T) {
	rep := model.ReasoningReport{
		Results: []model.RuleResult{
			{RuleID: "TA0006.IDENTITY_ANOMALY", Feasible: true},
			{RuleID: "TA0010.EXFIL", Feasible: true},
		},
	}
	hist := HistoryFile{
		Incidents: []HistoryEntry{
			{ID: "i1", RuleIDs: []string{"TA0006.IDENTITY_ANOMALY"}, Summary: "Identity anomaly", Playbook: "investigate-idp"},
			{ID: "i2", RuleIDs: []string{"TA0008.LATERAL"}, Summary: "Lateral movement"},
		},
	}
	similar, playbooks := SuggestSimilar(&rep, hist, SimilarConfig{Limit: 2, PlaybookLimit: 2})
	if len(similar) == 0 {
		t.Fatalf("expected similar incidents")
	}
	if len(playbooks) == 0 {
		t.Fatalf("expected playbooks")
	}
}

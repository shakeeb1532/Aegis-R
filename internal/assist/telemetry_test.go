package assist

import (
	"testing"

	"aman/internal/model"
)

func TestRecommendTelemetry(t *testing.T) {
	rep := model.ReasoningReport{
		Results: []model.RuleResult{
			{MissingEvidence: []model.EvidenceRequirement{{Type: "registry_run_key"}, {Type: "scheduled_task"}}},
			{MissingEvidence: []model.EvidenceRequirement{{Type: "registry_run_key"}}},
		},
	}
	hist := HistoryFile{
		Incidents: []HistoryEntry{
			{MissingEvidence: []string{"scheduled_task"}},
			{MissingEvidence: []string{"admin_group_change"}},
		},
	}
	rec, err := RecommendTelemetry(rep, hist, 3)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rec) == 0 {
		t.Fatalf("expected recommendations")
	}
}

package main

import (
	"testing"
	"time"

	"aman/internal/assist"
	"aman/internal/model"
)

func TestComputePilotMetrics(t *testing.T) {
	rep := model.ReasoningReport{
		AIOverlay: model.AIOverlaySummary{Enabled: true, CandidateCount: 3},
		AIAlerts: []model.AIAlert{
			{RuleID: "R1", Status: "escalated"},
			{RuleID: "R2", Status: "suppressed"},
			{RuleID: "R3", Status: "triaged"},
		},
	}
	history := assist.HistoryFile{
		Incidents: []assist.HistoryEntry{
			{ID: "i1", RuleIDs: []string{"R1"}, Outcome: "confirmed"},
			{ID: "i2", RuleIDs: []string{"R2"}, Outcome: "confirmed"},
		},
	}
	m := computePilotMetrics(rep, history, "report.json", "history.json")
	if m.CandidateCount != 3 {
		t.Fatalf("candidate count mismatch: %d", m.CandidateCount)
	}
	if m.EscalatedCount != 1 {
		t.Fatalf("escalated count mismatch: %d", m.EscalatedCount)
	}
	if m.EscalatedConfirmedCount != 1 {
		t.Fatalf("escalated confirmed mismatch: %d", m.EscalatedConfirmedCount)
	}
	if m.SuppressedLaterTrueCount != 1 {
		t.Fatalf("suppressed later true mismatch: %d", m.SuppressedLaterTrueCount)
	}
	if m.GeneratedAt.Before(time.Now().UTC().Add(-time.Minute)) {
		t.Fatalf("generated time too old")
	}
}

package overlay

import (
	"testing"
	"time"

	"aman/internal/logic"
	"aman/internal/model"
)

func TestBuildHighRecallAlertsAndFilter(t *testing.T) {
	events := []model.Event{
		{ID: "e1", Time: time.Now().UTC(), Type: "lsass_access"},
		{ID: "e2", Time: time.Now().UTC(), Type: "rundll32"},
	}
	rules := []logic.Rule{
		{
			ID:   "TA0006.CREDDUMP",
			Name: "Credential Dumping",
			Requirements: []model.EvidenceRequirement{
				{Type: "lsass_access"},
				{Type: "rundll32"},
			},
		},
	}
	alerts := BuildHighRecallAlerts(events, rules, 0.2, 10)
	if len(alerts) != 1 {
		t.Fatalf("expected one alert, got %d", len(alerts))
	}
	if alerts[0].RuleID != "TA0006.CREDDUMP" {
		t.Fatalf("unexpected rule id: %s", alerts[0].RuleID)
	}

	results := []model.RuleResult{{RuleID: "TA0006.CREDDUMP", Feasible: true, PrecondOK: true}}
	filtered, summary := ApplyCausalFilter(alerts, results)
	if len(filtered) != 1 {
		t.Fatalf("expected one filtered alert, got %d", len(filtered))
	}
	if filtered[0].Status != "escalated" {
		t.Fatalf("expected escalated status, got %s", filtered[0].Status)
	}
	if summary.EscalatedCount != 1 {
		t.Fatalf("expected escalated count 1, got %d", summary.EscalatedCount)
	}
}

func TestSourceProfilesIdentityMoreSensitiveThanEDR(t *testing.T) {
	rules := []logic.Rule{
		{
			ID:   "IDN.RULE",
			Name: "Identity Rule",
			Requirements: []model.EvidenceRequirement{
				{Type: "impossible_travel"},
				{Type: "mfa_method_removed"},
			},
		},
		{
			ID:   "EDR.RULE",
			Name: "EDR Rule",
			Requirements: []model.EvidenceRequirement{
				{Type: "lsass_access"},
				{Type: "rundll32"},
			},
		},
	}
	events := []model.Event{
		{
			ID:   "e1",
			Time: time.Now().UTC(),
			Type: "impossible_travel",
			Details: map[string]interface{}{
				"source": "okta",
			},
		},
		{
			ID:   "e2",
			Time: time.Now().UTC(),
			Type: "lsass_access",
			Details: map[string]interface{}{
				"source": "edr",
			},
		},
	}

	alerts := BuildHighRecallAlerts(events, rules, 0.20, 10)
	if len(alerts) != 2 {
		t.Fatalf("expected 2 alerts, got %d", len(alerts))
	}
	if alerts[0].RuleID != "IDN.RULE" {
		t.Fatalf("expected identity rule to rank first, got %s", alerts[0].RuleID)
	}
}

func TestAmanRemainsEscalationAuthority(t *testing.T) {
	events := []model.Event{
		{
			ID:   "e1",
			Time: time.Now().UTC(),
			Type: "impossible_travel",
			Details: map[string]interface{}{
				"source": "okta",
			},
		},
	}
	rules := []logic.Rule{
		{
			ID:   "IDN.RULE",
			Name: "Identity Rule",
			Requirements: []model.EvidenceRequirement{
				{Type: "impossible_travel"},
			},
		},
	}
	alerts := BuildHighRecallAlerts(events, rules, 0.20, 10)
	results := []model.RuleResult{
		{
			RuleID:           "IDN.RULE",
			Feasible:         false,
			PrecondOK:        false,
			PolicyImpossible: true,
		},
	}
	filtered, summary := ApplyCausalFilter(alerts, results)
	if len(filtered) != 1 {
		t.Fatalf("expected one filtered alert")
	}
	if filtered[0].Status != "suppressed" {
		t.Fatalf("expected suppressed status, got %s", filtered[0].Status)
	}
	if summary.SuppressedCount != 1 {
		t.Fatalf("expected suppressed count 1, got %d", summary.SuppressedCount)
	}
}

func TestBuildHighRecallAlerts_RequiresEvidenceHit(t *testing.T) {
	rules := []logic.Rule{
		{
			ID:   "R.NO_HITS",
			Name: "No Hits Rule",
			Requirements: []model.EvidenceRequirement{
				{Type: "never_seen_type"},
			},
		},
	}
	events := []model.Event{
		{ID: "e1", Time: time.Now().UTC(), Type: "different_type"},
	}
	alerts := BuildHighRecallAlerts(events, rules, 0.20, 10)
	if len(alerts) != 0 {
		t.Fatalf("expected no candidates without evidence hits, got %d", len(alerts))
	}
}

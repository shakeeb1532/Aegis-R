package logic

import (
	"testing"
	"time"

	"aman/internal/model"
)

func TestHasScopedContradictionMatchesSnakeCaseProcessGuids(t *testing.T) {
	events := []model.Event{
		{
			ID:   "e1",
			Time: time.Now().UTC(),
			Host: "win-01",
			User: "alice",
			Type: "lolbin_execution",
			Details: map[string]interface{}{
				"process_guid": "{11111111-1111-1111-1111-111111111111}",
			},
		},
		{
			ID:   "e2",
			Time: time.Now().UTC(),
			Host: "win-01",
			User: "alice",
			Type: "process_blocked",
			Details: map[string]interface{}{
				"process_guid": "{11111111-1111-1111-1111-111111111111}",
			},
		},
	}
	index := map[string][]int{
		"lolbin_execution": {0},
		"process_blocked":  {1},
	}
	rule := Rule{
		ID:              "TA0002.LOLBIN_CHAIN",
		Requirements:    []model.EvidenceRequirement{{Type: "lolbin_execution"}},
		Contradictions:  []string{"process_blocked"},
		RequiresContext: "host",
	}
	if !hasContradiction(rule, events, index) {
		t.Fatalf("expected scoped contradiction to match on snake_case process_guid")
	}
}

func TestHasScopedContradictionDoesNotCrossWindowsAuthScopes(t *testing.T) {
	events := []model.Event{
		{
			ID:   "e1",
			Time: time.Now().UTC(),
			Host: "dc-01",
			User: "alice",
			Type: "signin_success",
			Details: map[string]interface{}{
				"logon_id":   "0x1001",
				"source_ip":  "10.0.0.5",
				"logon_type": "10",
			},
		},
		{
			ID:   "e2",
			Time: time.Now().UTC(),
			Host: "dc-01",
			User: "alice",
			Type: "signin_denied_policy",
			Details: map[string]interface{}{
				"logon_id":   "0x1002",
				"source_ip":  "10.0.0.8",
				"logon_type": "10",
			},
		},
	}
	index := map[string][]int{
		"signin_success":       {0},
		"signin_denied_policy": {1},
	}
	rule := Rule{
		ID:              "TA0006.SIGNIN_SUCCESS",
		Requirements:    []model.EvidenceRequirement{{Type: "signin_success"}},
		Contradictions:  []string{"signin_denied_policy"},
		RequiresContext: "identity",
	}
	if hasContradiction(rule, events, index) {
		t.Fatalf("expected scoped contradiction to ignore different logon_id/source_ip scope")
	}
}

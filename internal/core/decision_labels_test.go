package core

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"aman/internal/env"
	"aman/internal/logic"
	"aman/internal/model"
	"aman/internal/state"
	"aman/internal/testutil"
)

type decisionExpectation struct {
	RuleID        string `json:"rule_id"`
	DecisionLabel string `json:"decision_label"`
	TicketStatus  string `json:"ticket_status"`
	ReasonCode    string `json:"reason_code"`
}

type decisionScenario struct {
	ID           string                `json:"id"`
	Description  string                `json:"description"`
	Events       any                   `json:"events"`
	Expectations []decisionExpectation `json:"expectations"`
}

type decisionScenarioFile struct {
	Scenarios []decisionScenario `json:"scenarios"`
}

func TestDecisionLabelsAndTickets(t *testing.T) {
	root := testutil.RepoRoot(t)
	data := readJSONFile(t, filepath.Join(root, "data", "scenarios_realistic.json"))
	var f decisionScenarioFile
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("decode scenarios: %v", err)
	}
	environment, err := env.Load(filepath.Join(root, "data", "env.json"))
	if err != nil {
		t.Fatalf("env load: %v", err)
	}
	for _, s := range f.Scenarios {
		if len(s.Expectations) == 0 {
			continue
		}
		events := coerceEvents(t, s.Events)
		out := Assess(events, logic.DefaultRules(), environment, state.New())
		for _, exp := range s.Expectations {
			var got *model.RuleResult
			for i := range out.Reasoning.Results {
				if out.Reasoning.Results[i].RuleID == exp.RuleID {
					got = &out.Reasoning.Results[i]
					break
				}
			}
			if got == nil {
				t.Fatalf("scenario %s missing rule %s", s.ID, exp.RuleID)
			}
			if exp.DecisionLabel != "" && got.DecisionLabel != exp.DecisionLabel {
				t.Fatalf("scenario %s rule %s decision label=%s want=%s", s.ID, exp.RuleID, got.DecisionLabel, exp.DecisionLabel)
			}
			if exp.ReasonCode != "" && got.ReasonCode != exp.ReasonCode {
				t.Fatalf("scenario %s rule %s reason code=%s want=%s", s.ID, exp.RuleID, got.ReasonCode, exp.ReasonCode)
			}
			if exp.TicketStatus != "" {
				if got.ThreadID == "" {
					t.Fatalf("scenario %s rule %s expected ticket status %s but thread missing", s.ID, exp.RuleID, exp.TicketStatus)
				}
				var status string
				for _, tkt := range out.State.Tickets {
					if tkt.ThreadID == got.ThreadID {
						status = tkt.Status
						break
					}
				}
				if status == "" {
					t.Fatalf("scenario %s rule %s ticket not found for thread %s", s.ID, exp.RuleID, got.ThreadID)
				}
				if status != exp.TicketStatus {
					t.Fatalf("scenario %s rule %s ticket status=%s want=%s", s.ID, exp.RuleID, status, exp.TicketStatus)
				}
			}
		}
	}
}

func readJSONFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}

func coerceEvents(t *testing.T, v any) []model.Event {
	t.Helper()
	if ev, ok := v.([]model.Event); ok {
		return ev
	}
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal events: %v", err)
	}
	var events []model.Event
	if err := json.Unmarshal(data, &events); err != nil {
		t.Fatalf("unmarshal events: %v", err)
	}
	return events
}

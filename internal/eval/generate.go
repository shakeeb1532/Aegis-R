package eval

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"aegisr/internal/logic"
	"aegisr/internal/model"
)

func GenerateScenarios(rules []logic.Rule) ScenariosFile {
	scenarios := []Scenario{}
	for _, r := range rules {
		scenarios = append(scenarios, scenarioForRule(r, OutcomeFeasible))
		scenarios = append(scenarios, scenarioForRule(r, OutcomeIncomplete))
		scenarios = append(scenarios, scenarioForRule(r, OutcomeImpossible))
	}
	return ScenariosFile{Scenarios: scenarios}
}

func SaveScenarios(path string, f ScenariosFile) error {
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func scenarioForRule(r logic.Rule, outcome Outcome) Scenario {
	events := []model.Event{}
	base := time.Now().UTC()
	id := fmt.Sprintf("%s-%s", r.ID, outcome)

	// Add preconditions evidence when needed (except impossible)
	if outcome != OutcomeImpossible {
		events = append(events, precondEvents(r.Preconds, base)...)
	}

	// Add requirements depending on outcome
	reqs := r.Requirements
	for i, req := range reqs {
		if outcome == OutcomeIncomplete && i == 0 {
			continue // drop one requirement
		}
		events = append(events, model.Event{ID: fmt.Sprintf("e-%s-%d", r.ID, i), Time: base.Add(time.Duration(i) * time.Second), Host: "host-1", User: "alice", Type: req.Type})
	}

	label := Label{RuleID: r.ID, Outcome: outcome}
	return Scenario{
		ID:          id,
		Description: fmt.Sprintf("%s scenario for %s", outcome, r.Name),
		Events:      events,
		Labels:      []Label{label},
	}
}

func precondEvents(preconds []string, base time.Time) []model.Event {
	events := []model.Event{}
	add := func(t string, idx int) {
		events = append(events, model.Event{ID: fmt.Sprintf("p-%s-%d", t, idx), Time: base.Add(time.Duration(idx) * time.Second), Host: "host-1", User: "alice", Type: t})
	}
	idx := 0
	for _, p := range preconds {
		switch p {
		case "initial_access":
			add("email_attachment_open", idx)
			idx++
			add("macro_execution", idx)
		case "privilege_escalation":
			add("token_manipulation", idx)
		case "credential_access":
			add("lsass_access", idx)
		case "c2_established":
			add("beacon_outbound", idx)
		}
		idx++
	}
	return events
}

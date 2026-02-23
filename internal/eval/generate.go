package eval

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"aman/internal/logic"
	"aman/internal/model"
)

type ScenarioOptions struct {
	Multiplier int
	Noise      bool
}

func GenerateScenarios(rules []logic.Rule) ScenariosFile {
	return GenerateScenariosWithOptions(rules, ScenarioOptions{Multiplier: 1, Noise: false})
}

func GenerateScenariosWithOptions(rules []logic.Rule, opts ScenarioOptions) ScenariosFile {
	if opts.Multiplier <= 0 {
		opts.Multiplier = 1
	}
	scenarios := []Scenario{}
	for _, r := range rules {
		for i := 0; i < opts.Multiplier; i++ {
			scenarios = append(scenarios, scenarioForRule(r, OutcomeFeasible, i, opts))
			scenarios = append(scenarios, scenarioForRule(r, OutcomeIncomplete, i, opts))
			scenarios = append(scenarios, scenarioForRule(r, OutcomeImpossible, i, opts))
		}
	}
	return ScenariosFile{Scenarios: scenarios}
}

func SaveScenarios(path string, f ScenariosFile) error {
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func scenarioForRule(r logic.Rule, outcome Outcome, variant int, opts ScenarioOptions) Scenario {
	events := []model.Event{}
	base := time.Now().UTC()
	id := fmt.Sprintf("%s-%s-%d", r.ID, outcome, variant)

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

	if outcome == OutcomeImpossible {
		contradictions := logic.ContradictionTypes(r.ID)
		if len(contradictions) > 0 {
			for i, t := range contradictions {
				events = append(events, model.Event{ID: fmt.Sprintf("c-%s-%d", r.ID, i), Time: base.Add(time.Duration(i) * time.Second), Host: "host-1", User: "alice", Type: t})
			}
		} else {
			events = append(events, precondViolationEvents(r.Preconds, base)...)
		}
	}

	if opts.Noise {
		events = append(events, noiseEvents(base, variant)...)
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

func precondViolationEvents(preconds []string, base time.Time) []model.Event {
	events := []model.Event{}
	add := func(t string, idx int) {
		events = append(events, model.Event{ID: fmt.Sprintf("v-%s-%d", t, idx), Time: base.Add(time.Duration(idx) * time.Second), Host: "host-1", User: "alice", Type: t})
	}
	idx := 0
	for _, p := range preconds {
		switch p {
		case "privilege_escalation":
			add("privilege_escalation_blocked", idx)
		case "credential_access":
			add("access_denied", idx)
		case "c2_established":
			add("egress_blocked", idx)
		case "initial_access":
			add("login_denied", idx)
		}
		idx++
	}
	return events
}

func noiseEvents(base time.Time, variant int) []model.Event {
	noise := []string{
		"dns_query",
		"file_read",
		"process_creation_benign",
		"user_login_success",
		"service_start",
	}
	out := []model.Event{}
	for i := 0; i < 2; i++ {
		t := noise[(variant+i)%len(noise)]
		out = append(out, model.Event{ID: fmt.Sprintf("n-%s-%d", t, i), Time: base.Add(time.Duration(100+i) * time.Second), Host: "host-1", User: "alice", Type: t})
	}
	return out
}

package eval

import (
	"encoding/json"

	aenv "aman/internal/env"
	"aman/internal/logic"
	"aman/internal/model"
)

func Score(scenarios ScenariosFile, rules []logic.Rule) Report {
	byClass := map[Outcome]ClassMetrics{
		OutcomeFeasible:   {},
		OutcomeIncomplete: {},
		OutcomeImpossible: {},
	}
	byRuleTotal := map[string]int{}
	byRuleCorrect := map[string]int{}
	mismatches := []Mismatch{}

	correct := 0
	total := 0

	for _, s := range scenarios.Scenarios {
		events, err := coerceEvents(s.Events)
		if err != nil {
			continue
		}
		environment, err := coerceEnvironment(s.Environment)
		if err != nil {
			continue
		}
		rep := reasonWithOptionalEnv(events, rules, environment)
		pred := map[string]Outcome{}
		for _, r := range rep.Results {
			pred[r.RuleID] = classify(r)
		}
		for _, label := range s.Labels {
			actual := label.Outcome
			p := pred[label.RuleID]
			if p == actual {
				correct++
				byRuleCorrect[label.RuleID]++
			} else {
				mismatches = append(mismatches, Mismatch{ScenarioID: s.ID, RuleID: label.RuleID, Expected: actual, Actual: p})
			}
			total++
			byRuleTotal[label.RuleID]++

			// class metrics
			for _, cls := range []Outcome{OutcomeFeasible, OutcomeIncomplete, OutcomeImpossible} {
				cm := byClass[cls]
				if p == cls && actual == cls {
					cm.TP++
				} else if p == cls && actual != cls {
					cm.FP++
				} else if p != cls && actual == cls {
					cm.FN++
				}
				byClass[cls] = cm
			}
		}
	}

	for cls, cm := range byClass {
		if cm.TP+cm.FP > 0 {
			cm.Precision = float64(cm.TP) / float64(cm.TP+cm.FP)
		}
		if cm.TP+cm.FN > 0 {
			cm.Recall = float64(cm.TP) / float64(cm.TP+cm.FN)
		}
		byClass[cls] = cm
	}

	byRuleAcc := map[string]float64{}
	for id, total := range byRuleTotal {
		if total > 0 {
			byRuleAcc[id] = float64(byRuleCorrect[id]) / float64(total)
		}
	}

	acc := 0.0
	if total > 0 {
		acc = float64(correct) / float64(total)
	}

	return Report{
		Total:      total,
		Accuracy:   acc,
		ByClass:    byClass,
		ByRuleID:   byRuleAcc,
		Mismatches: mismatches,
	}
}

func reasonWithOptionalEnv(events []model.Event, rules []logic.Rule, environment aenv.Environment) model.ReasoningReport {
	if len(environment.Hosts) == 0 && len(environment.Identities) == 0 && len(environment.TrustBoundaries) == 0 {
		return logic.Reason(events, rules)
	}
	return logic.ReasonWithEnv(events, rules, environment)
}

func coerceEvents(v any) ([]model.Event, error) {
	if ev, ok := v.([]model.Event); ok {
		return ev, nil
	}
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var events []model.Event
	if err := json.Unmarshal(data, &events); err != nil {
		return nil, err
	}
	return events, nil
}

func classify(r model.RuleResult) Outcome {
	if r.PolicyImpossible || r.Conflicted {
		return OutcomeImpossible
	}
	if r.Feasible {
		return OutcomeFeasible
	}
	if len(r.MissingEvidence) > 0 {
		return OutcomeIncomplete
	}
	return OutcomeImpossible
}

package eval

import (
	"encoding/json"
	"os"

	aenv "aman/internal/env"
	"aman/internal/ops"
)

type Outcome string

const (
	OutcomeFeasible   Outcome = "feasible"
	OutcomeIncomplete Outcome = "incomplete"
	OutcomeImpossible Outcome = "impossible"
)

type Label struct {
	RuleID  string  `json:"rule_id"`
	Outcome Outcome `json:"outcome"`
}

type Scenario struct {
	ID          string  `json:"id"`
	Description string  `json:"description"`
	Events      any     `json:"events"`
	Environment any     `json:"environment,omitempty"`
	Labels      []Label `json:"labels"`
}

type ScenariosFile struct {
	Scenarios []Scenario `json:"scenarios"`
}

type ClassMetrics struct {
	TP        int     `json:"tp"`
	FP        int     `json:"fp"`
	FN        int     `json:"fn"`
	Precision float64 `json:"precision"`
	Recall    float64 `json:"recall"`
}

type Report struct {
	Total      int                      `json:"total"`
	Accuracy   float64                  `json:"accuracy"`
	ByClass    map[Outcome]ClassMetrics `json:"by_class"`
	ByRuleID   map[string]float64       `json:"accuracy_by_rule"`
	Mismatches []Mismatch               `json:"mismatches"`
}

type Mismatch struct {
	ScenarioID string  `json:"scenario_id"`
	RuleID     string  `json:"rule_id"`
	Expected   Outcome `json:"expected"`
	Actual     Outcome `json:"actual"`
}

func LoadScenarios(path string) (ScenariosFile, error) {
	var f ScenariosFile
	if !ops.IsSafePath(path) {
		return f, os.ErrInvalid
	}
	//nolint:gosec // path validated via IsSafePath
	// #nosec G304
	data, err := os.ReadFile(path)
	if err != nil {
		return f, err
	}
	if err := json.Unmarshal(data, &f); err != nil {
		return f, err
	}
	return f, nil
}

func coerceEnvironment(v any) (aenv.Environment, error) {
	var environment aenv.Environment
	if v == nil {
		return environment, nil
	}
	if envValue, ok := v.(aenv.Environment); ok {
		return envValue, nil
	}
	data, err := json.Marshal(v)
	if err != nil {
		return environment, err
	}
	if err := json.Unmarshal(data, &environment); err != nil {
		return environment, err
	}
	if err := aenv.Validate(environment); err != nil {
		return environment, err
	}
	return environment, nil
}

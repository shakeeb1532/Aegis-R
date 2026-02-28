//go:build tools
// +build tools

package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"aman/internal/eval"
	"aman/internal/logic"
	"aman/internal/model"
	"aman/internal/ops"
)

type mismatchRow struct {
	ScenarioID      string
	RuleID          string
	Expected        string
	Actual          string
	ReasonCode      string
	MissingEvidence string
	DisagreeReason  string
}

func main() {
	scenarioPath := flag.String("scenarios", "data/scenarios_realistic.json", "scenarios json")
	rulesPath := flag.String("rules", "data/rules.json", "rules json")
	outMD := flag.String("out-md", "docs/mismatch_report.md", "markdown output")
	outCSV := flag.String("out-csv", "docs/mismatch_report.csv", "csv output")
	if err := flag.CommandLine.Parse(os.Args[1:]); err != nil {
		panic(err)
	}

	if !ops.IsSafePath(*scenarioPath) || !ops.IsSafePath(*rulesPath) {
		panic("unsafe path")
	}

	scenarios, err := eval.LoadScenarios(*scenarioPath)
	if err != nil {
		panic(err)
	}
	rules, err := logic.LoadRulesCombined(*rulesPath, "")
	if err != nil {
		panic(err)
	}

	byID := map[string]logic.Rule{}
	for _, r := range rules {
		byID[r.ID] = r
	}

	rows := []mismatchRow{}
	for _, s := range scenarios.Scenarios {
		events, err := coerceEvents(s.Events)
		if err != nil {
			panic(err)
		}
		rep := logic.ReasonWithMetrics(events, rules, nil, false)
		resByID := map[string]model.RuleResult{}
		for _, r := range rep.Results {
			resByID[r.RuleID] = r
		}
		for _, label := range s.Labels {
			rule := byID[label.RuleID]
			if rule.ID == "" {
				continue
			}
			result, ok := resByID[label.RuleID]
			if !ok {
				continue
			}
			actual := classify(result)
			if actual != label.Outcome {
				rows = append(rows, mismatchRow{
					ScenarioID:      s.ID,
					RuleID:          label.RuleID,
					Expected:        string(label.Outcome),
					Actual:          string(actual),
					ReasonCode:      result.ReasonCode,
					MissingEvidence: joinMissing(result.MissingEvidence),
					DisagreeReason:  "",
				})
			}
		}
	}

	writeCSV(*outCSV, rows)
	writeMarkdown(*outMD, *scenarioPath, *rulesPath, rows)
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

func classify(r model.RuleResult) eval.Outcome {
	if r.PolicyImpossible || r.Conflicted {
		return eval.OutcomeImpossible
	}
	if r.Feasible {
		return eval.OutcomeFeasible
	}
	if len(r.MissingEvidence) > 0 {
		return eval.OutcomeIncomplete
	}
	return eval.OutcomeImpossible
}

func joinMissing(m []model.EvidenceRequirement) string {
	if len(m) == 0 {
		return ""
	}
	types := make([]string, 0, len(m))
	for _, r := range m {
		if r.Type != "" {
			types = append(types, r.Type)
		}
	}
	sort.Strings(types)
	return strings.Join(types, ";")
}

func writeCSV(path string, rows []mismatchRow) {
	if path == "" {
		return
	}
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	f, err := os.Create(path)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	w := csv.NewWriter(f)
	_ = w.Write([]string{"scenario_id", "rule_id", "expected", "aman_verdict", "reason_code", "missing_evidence", "disagree_reason"})
	for _, r := range rows {
		_ = w.Write([]string{
			r.ScenarioID, r.RuleID, r.Expected, r.Actual, r.ReasonCode, r.MissingEvidence, r.DisagreeReason,
		})
	}
	w.Flush()
}

func writeMarkdown(path, scenarioPath, rulesPath string, rows []mismatchRow) {
	if path == "" {
		return
	}
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	f, err := os.Create(path)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	fmt.Fprintf(f, "# Mismatch Report\n\n")
	fmt.Fprintf(f, "Generated: %s\n\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintf(f, "- Scenarios: %s\n", scenarioPath)
	fmt.Fprintf(f, "- Rules: %s\n", rulesPath)
	fmt.Fprintf(f, "- Mismatches: %d\n\n", len(rows))
	if len(rows) == 0 {
		fmt.Fprintln(f, "No mismatches.")
		return
	}
	fmt.Fprintln(f, "| scenario_id | rule_id | expected | Aman verdict | reason_code | missing_evidence | disagree_reason |")
	fmt.Fprintln(f, "| --- | --- | --- | --- | --- | --- | --- |")
	for _, r := range rows {
		missing := r.MissingEvidence
		if missing == "" {
			missing = "-"
		}
		disagree := r.DisagreeReason
		if disagree == "" {
			disagree = "-"
		}
		fmt.Fprintf(f, "| %s | %s | %s | %s | %s | %s | %s |\n",
			r.ScenarioID, r.RuleID, r.Expected, r.Actual, r.ReasonCode, missing, disagree)
	}
}

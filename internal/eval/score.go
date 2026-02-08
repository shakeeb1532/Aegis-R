package eval

import (
	"encoding/json"

	"aegisr/internal/logic"
	"aegisr/internal/model"
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
	calibration := buildCalibrationBins(10)

	for _, s := range scenarios.Scenarios {
		events, err := coerceEvents(s.Events)
		if err != nil {
			continue
		}
		rep := logic.Reason(events, rules)
		pred := map[string]Outcome{}
		confidence := map[string]float64{}
		for _, r := range rep.Results {
			pred[r.RuleID] = classify(r)
			confidence[r.RuleID] = clamp01(r.Confidence)
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
			updateCalibration(calibration, confidence[label.RuleID], p == actual)

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
		Total:           total,
		Accuracy:        acc,
		ByClass:         byClass,
		ByRuleID:        byRuleAcc,
		Mismatches:      mismatches,
		Calibration:     finalizeCalibration(calibration),
		CalibrationNote: "Calibration uses correctness vs reported confidence, bucketed into 10 bins.",
	}
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
	if r.Feasible {
		return OutcomeFeasible
	}
	if len(r.MissingEvidence) > 0 {
		return OutcomeIncomplete
	}
	return OutcomeImpossible
}

type calibrationBucket struct {
	Lower     float64
	Upper     float64
	Count     int
	Correct   int
	ConfTotal float64
}

func buildCalibrationBins(count int) []calibrationBucket {
	if count <= 0 {
		count = 10
	}
	bins := make([]calibrationBucket, count)
	step := 1.0 / float64(count)
	for i := 0; i < count; i++ {
		bins[i] = calibrationBucket{
			Lower: float64(i) * step,
			Upper: float64(i+1) * step,
		}
	}
	return bins
}

func updateCalibration(bins []calibrationBucket, confidence float64, correct bool) {
	if len(bins) == 0 {
		return
	}
	idx := int(confidence * float64(len(bins)))
	if idx >= len(bins) {
		idx = len(bins) - 1
	}
	bins[idx].Count++
	if correct {
		bins[idx].Correct++
	}
	bins[idx].ConfTotal += confidence
}

func finalizeCalibration(bins []calibrationBucket) []CalibrationBin {
	out := make([]CalibrationBin, 0, len(bins))
	for _, b := range bins {
		avg := 0.0
		acc := 0.0
		if b.Count > 0 {
			avg = b.ConfTotal / float64(b.Count)
			acc = float64(b.Correct) / float64(b.Count)
		}
		out = append(out, CalibrationBin{
			Lower:         b.Lower,
			Upper:         b.Upper,
			Count:         b.Count,
			Correct:       b.Correct,
			Accuracy:      acc,
			AvgConfidence: avg,
		})
	}
	return out
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

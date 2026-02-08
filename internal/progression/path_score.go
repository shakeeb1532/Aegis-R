package progression

import (
	"sort"
	"time"

	"aegisr/internal/state"
)

var stageOrder = map[string]int{
	"identity_auth":   1,
	"host_execution":  2,
	"lateral_network": 3,
	"data_impact":     4,
}

type pathAgg struct {
	count     int
	sumConf   float64
	lastSeen  time.Time
}

// BuildPathScores produces a probabilistic score per stage to indicate likely attacker progression.
func BuildPathScores(events []state.ProgressEvent, now time.Time) ([]state.PathScore, float64) {
	if len(events) == 0 {
		return nil, 0
	}
	agg := map[string]*pathAgg{}
	for _, e := range events {
		stage := e.Stage
		if stage == "" {
			continue
		}
		entry := agg[stage]
		if entry == nil {
			entry = &pathAgg{}
			agg[stage] = entry
		}
		entry.count++
		entry.sumConf += e.Confidence
		if e.Time.After(entry.lastSeen) {
			entry.lastSeen = e.Time
		}
	}
	out := make([]state.PathScore, 0, len(agg))
	maxStage := 0
	for _, v := range stageOrder {
		if v > maxStage {
			maxStage = v
		}
	}
	for stage, entry := range agg {
		avgConf := 0.0
		if entry.count > 0 {
			avgConf = entry.sumConf / float64(entry.count)
		}
		recency := recencyScore(entry.lastSeen, now)
		stageScore := float64(stageOrder[stage]) / float64(maxStage)
		score := 0.4*avgConf + 0.3*recency + 0.3*stageScore
		out = append(out, state.PathScore{
			Stage:         stage,
			Score:         clampScore(score),
			EvidenceCount: entry.count,
			AvgConfidence: avgConf,
			LastSeen:      entry.lastSeen,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score == out[j].Score {
			return out[i].Stage < out[j].Stage
		}
		return out[i].Score > out[j].Score
	})
	overall := 0.0
	for _, s := range out {
		overall += s.Score
	}
	if len(out) > 0 {
		overall = overall / float64(len(out))
	}
	return out, clampScore(overall)
}

func recencyScore(lastSeen time.Time, now time.Time) float64 {
	if lastSeen.IsZero() {
		return 0.3
	}
	age := now.Sub(lastSeen)
	switch {
	case age <= time.Hour:
		return 1.0
	case age <= 6*time.Hour:
		return 0.85
	case age <= 24*time.Hour:
		return 0.7
	case age <= 72*time.Hour:
		return 0.5
	default:
		return 0.3
	}
}

func clampScore(v float64) float64 {
	if v < 0.05 {
		return 0.05
	}
	if v > 0.98 {
		return 0.98
	}
	return v
}

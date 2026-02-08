package progression

import (
	"sort"

	"aegisr/internal/state"
)

type summaryAgg struct {
	principals map[string]bool
	assets     map[string]bool
	lastSeen   state.ProgressEvent
	sumConf    float64
	count      int
}

// BuildPositionSummaries aggregates progression events into per-stage summaries.
func BuildPositionSummaries(events []state.ProgressEvent) []state.PositionSummary {
	if len(events) == 0 {
		return nil
	}
	agg := map[string]*summaryAgg{}
	for _, e := range events {
		stage := e.Stage
		if stage == "" {
			continue
		}
		entry, ok := agg[stage]
		if !ok {
			entry = &summaryAgg{
				principals: map[string]bool{},
				assets:     map[string]bool{},
			}
			agg[stage] = entry
		}
		if e.Principal != "" {
			entry.principals[e.Principal] = true
		}
		if e.Asset != "" {
			entry.assets[e.Asset] = true
		}
		if e.Time.After(entry.lastSeen.Time) {
			entry.lastSeen = e
		}
		entry.sumConf += e.Confidence
		entry.count++
	}
	out := make([]state.PositionSummary, 0, len(agg))
	for stage, entry := range agg {
		conf := 0.0
		if entry.count > 0 {
			conf = entry.sumConf / float64(entry.count)
		}
		out = append(out, state.PositionSummary{
			Stage:          stage,
			PrincipalCount: len(entry.principals),
			AssetCount:     len(entry.assets),
			LastSeen:       entry.lastSeen.Time,
			Confidence:     conf,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Stage == out[j].Stage {
			return out[i].Confidence > out[j].Confidence
		}
		return out[i].Stage < out[j].Stage
	})
	return out
}

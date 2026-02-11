package assist

import (
	"encoding/json"
	"errors"
	"os"
	"sort"
	"strings"

	"aegisr/internal/model"
	"aegisr/internal/ops"
)

type HistoryEntry struct {
	ID              string   `json:"id"`
	RuleID          string   `json:"rule_id"`
	RuleIDs         []string `json:"rule_ids"`
	Outcome         string   `json:"outcome"`
	Category        string   `json:"category"`
	MissingEvidence []string `json:"missing_evidence"`
	Summary         string   `json:"summary"`
	Playbook        string   `json:"playbook"`
}

type HistoryFile struct {
	Incidents []HistoryEntry `json:"incidents"`
}

func LoadHistory(path string) (HistoryFile, error) {
	if path == "" {
		return HistoryFile{}, nil
	}
	if !ops.IsSafePath(path) {
		return HistoryFile{}, os.ErrInvalid
	}
	//nolint:gosec // path validated via IsSafePath
	// #nosec G304
	data, err := os.ReadFile(path)
	if err != nil {
		return HistoryFile{}, err
	}
	var h HistoryFile
	if err := json.Unmarshal(data, &h); err != nil {
		return HistoryFile{}, err
	}
	return h, nil
}

func RecommendTelemetry(rep model.ReasoningReport, history HistoryFile, limit int) ([]string, error) {
	if limit <= 0 {
		return nil, errors.New("limit must be positive")
	}
	counts := map[string]int{}
	for _, r := range rep.Results {
		for _, m := range r.MissingEvidence {
			counts[m.Type]++
		}
	}
	for _, inc := range history.Incidents {
		for _, miss := range inc.MissingEvidence {
			if miss == "" {
				continue
			}
			counts[miss] += 2
		}
	}
	type kv struct {
		Key string
		Val int
	}
	pairs := []kv{}
	for k, v := range counts {
		if strings.TrimSpace(k) == "" {
			continue
		}
		pairs = append(pairs, kv{Key: k, Val: v})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].Val == pairs[j].Val {
			return pairs[i].Key < pairs[j].Key
		}
		return pairs[i].Val > pairs[j].Val
	})
	out := []string{}
	for i := 0; i < len(pairs) && i < limit; i++ {
		out = append(out, pairs[i].Key)
	}
	return out, nil
}

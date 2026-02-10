package explain

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"aegisr/internal/model"
)

type Options struct {
	Endpoint string
	Timeout  time.Duration
}

type Response struct {
	Explanation string   `json:"explanation"`
	Steps       []string `json:"steps"`
	Source      string   `json:"source"`
}

type request struct {
	Reasoning   model.ReasoningReport `json:"reasoning"`
	Style       string               `json:"style"`
	StepsLimit  int                  `json:"steps_limit"`
}

func Generate(rep model.ReasoningReport, opts Options) (Response, error) {
	if opts.Endpoint != "" {
		resp, err := callEndpoint(rep, opts)
		if err != nil {
			return Response{}, err
		}
		resp.Source = "llm"
		return resp, nil
	}
	resp := localExplain(rep)
	resp.Source = "local"
	return resp, nil
}

func callEndpoint(rep model.ReasoningReport, opts Options) (Response, error) {
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 8 * time.Second
	}
	reqBody := request{
		Reasoning:  rep,
		Style:      "concise",
		StepsLimit: 5,
	}
	data, err := json.Marshal(reqBody)
	if err != nil {
		return Response{}, err
	}
	httpClient := &http.Client{Timeout: timeout}
	httpReq, err := http.NewRequest("POST", opts.Endpoint, bytes.NewReader(data))
	if err != nil {
		return Response{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	res, err := httpClient.Do(httpReq)
	if err != nil {
		return Response{}, err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return Response{}, errors.New("llm endpoint returned non-2xx status")
	}
	var out Response
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		return Response{}, err
	}
	return out, nil
}

func localExplain(rep model.ReasoningReport) Response {
	feasible := 0
	incomplete := 0
	impossible := 0
	for _, r := range rep.Results {
		if r.Feasible {
			feasible++
		} else if len(r.MissingEvidence) > 0 {
			incomplete++
		} else {
			impossible++
		}
	}

	feasibleDetails := feasibleSummary(rep.Results, 5)
	incompleteDetails := incompleteSummary(rep.Results, 6)
	topGaps := topMissing(rep.Results, 3)

	summary := fmt.Sprintf(
		"%d feasible findings, %d incomplete findings, %d impossible findings.",
		feasible, incomplete, impossible,
	)
	lines := []string{summary}
	if len(feasibleDetails) > 0 {
		lines = append(lines, "Feasible findings to review:")
		lines = append(lines, feasibleDetails...)
	}
	if len(incompleteDetails) > 0 {
		lines = append(lines, "Incomplete findings missing telemetry:")
		lines = append(lines, incompleteDetails...)
	}
	if len(topGaps) > 0 {
		lines = append(lines, "Most common missing evidence: "+strings.Join(topGaps, ", "))
	}

	steps := []string{}
	if len(feasibleDetails) > 0 {
		steps = append(steps, "Review feasible findings in order of confidence and evidence strength")
	}
	if len(incompleteDetails) > 0 {
		steps = append(steps, "Collect missing telemetry for top incomplete findings")
	}
	if len(topGaps) > 0 {
		steps = append(steps, "Prioritize collection for: "+strings.Join(topGaps, ", "))
	}

	return Response{
		Explanation: strings.Join(lines, "\n"),
		Steps:       steps,
	}
}

func topRules(results []model.RuleResult, pred func(model.RuleResult) bool) []string {
	out := []string{}
	for _, r := range results {
		if pred(r) {
			out = append(out, r.RuleID)
		}
	}
	sort.Strings(out)
	if len(out) > 4 {
		return out[:4]
	}
	return out
}

func topMissing(results []model.RuleResult, limit int) []string {
	count := map[string]int{}
	for _, r := range results {
		for _, m := range r.MissingEvidence {
			count[m.Type]++
		}
	}
	type kv struct {
		Key string
		Val int
	}
	var pairs []kv
	for k, v := range count {
		pairs = append(pairs, kv{k, v})
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
	return out
}

func joinOrNA(vals []string) string {
	if len(vals) == 0 {
		return "none"
	}
	return strings.Join(vals, ", ")
}

func feasibleSummary(results []model.RuleResult, limit int) []string {
	type item struct {
		ID         string
		Confidence float64
		Evidence   []string
	}
	items := []item{}
	for _, r := range results {
		if !r.Feasible {
			continue
		}
		items = append(items, item{ID: r.RuleID, Confidence: r.Confidence, Evidence: r.SupportingEventIDs})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Confidence == items[j].Confidence {
			return items[i].ID < items[j].ID
		}
		return items[i].Confidence > items[j].Confidence
	})
	out := []string{}
	for i := 0; i < len(items) && i < limit; i++ {
		ev := "no evidence ids"
		if len(items[i].Evidence) > 0 {
			ev = strings.Join(items[i].Evidence, ", ")
		}
		out = append(out, fmt.Sprintf("- %s (confidence %.2f, evidence %s)", items[i].ID, items[i].Confidence, ev))
	}
	return out
}

func incompleteSummary(results []model.RuleResult, limit int) []string {
	out := []string{}
	for _, r := range results {
		if r.Feasible || len(r.MissingEvidence) == 0 {
			continue
		}
		missing := []string{}
		for _, m := range r.MissingEvidence {
			missing = append(missing, m.Type)
		}
		sort.Strings(missing)
		out = append(out, fmt.Sprintf("- %s missing %s", r.RuleID, strings.Join(missing, ", ")))
	}
	sort.Strings(out)
	if len(out) > limit {
		return out[:limit]
	}
	return out
}

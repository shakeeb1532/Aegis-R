package uiapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

type reportFile struct {
	GeneratedAt string `json:"generated_at"`
	Summary     string `json:"summary"`
	Reasoning   struct {
		GeneratedAt string                      `json:"generated_at"`
		Summary     string                      `json:"summary"`
		Results     []reportFileReasoningResult `json:"results"`
		Threads     []struct {
			ID         string   `json:"id"`
			Host       string   `json:"host"`
			Principal  string   `json:"principal"`
			FirstSeen  string   `json:"first_seen"`
			LastSeen   string   `json:"last_seen"`
			RuleIDs    []string `json:"rule_ids"`
			Confidence float64  `json:"confidence"`
			Reason     string   `json:"reason"`
		} `json:"threads"`
		Tickets []struct {
			ID            string   `json:"id"`
			ThreadID      string   `json:"thread_id"`
			Host          string   `json:"host"`
			Principal     string   `json:"principal"`
			Status        string   `json:"status"`
			DecisionLabel string   `json:"decision_label"`
			ReasonCode    string   `json:"reason_code"`
			CreatedAt     string   `json:"created_at"`
			UpdatedAt     string   `json:"updated_at"`
			RuleIDs       []string `json:"rule_ids"`
		} `json:"tickets"`
	} `json:"reasoning"`
	NextMoves    []string `json:"next_moves"`
	DriftSignals []string `json:"drift_signals"`
	Findings     []string `json:"findings"`
}

type reportFileReasoningResult struct {
	RuleID          string  `json:"rule_id"`
	Name            string  `json:"name"`
	Feasible        bool    `json:"feasible"`
	PrecondOK       bool    `json:"precond_ok"`
	Confidence      float64 `json:"confidence"`
	MissingEvidence []struct {
		Type        string `json:"type"`
		Description string `json:"description"`
	} `json:"missing_evidence"`
	SupportingEventIDs []string `json:"supporting_event_ids"`
	Explanation        string   `json:"explanation"`
	GapNarrative       string   `json:"gap_narrative"`
	ReasonCode         string   `json:"reason_code"`
	DecisionLabel      string   `json:"decision_label"`
	ThreadID           string   `json:"thread_id"`
	ThreadConfidence   float64  `json:"thread_confidence"`
	ThreadReason       string   `json:"thread_reason"`
}

func loadReport(path string) (*reportFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	idx := bytes.IndexByte(data, '{')
	if idx == -1 {
		return nil, fmt.Errorf("report json not found")
	}
	var out reportFile
	if err := json.Unmarshal(data[idx:], &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func verdictFromResult(feasible bool, precondOK bool) string {
	if feasible {
		return "POSSIBLE"
	}
	if !precondOK {
		return "IMPOSSIBLE"
	}
	return "INCOMPLETE"
}

func summarizeEvidence(ids []string) []string {
	if len(ids) == 0 {
		return []string{"no direct evidence linked"}
	}
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, "event "+id)
	}
	return out
}

func summarizeGaps(missing []struct {
	Type        string `json:"type"`
	Description string `json:"description"`
}) []string {
	if len(missing) == 0 {
		return []string{}
	}
	out := make([]string, 0, len(missing))
	for _, gap := range missing {
		if gap.Description != "" {
			out = append(out, gap.Description)
			continue
		}
		out = append(out, gap.Type)
	}
	return out
}

func latestTimestamp(ts string) string {
	if ts == "" {
		return ""
	}
	if t, err := time.Parse(time.RFC3339, ts); err == nil {
		return t.Format("2006-01-02 15:04 UTC")
	}
	return ts
}

func buildOverview(r *reportFile) OverviewResponse {
	feasibleCount := 0
	gapSet := map[string]struct{}{}
	for _, res := range r.Reasoning.Results {
		if res.Feasible {
			feasibleCount++
		}
		for _, gap := range res.MissingEvidence {
			if gap.Description != "" {
				gapSet[gap.Description] = struct{}{}
			} else if gap.Type != "" {
				gapSet[gap.Type] = struct{}{}
			}
		}
	}
	gapList := make([]string, 0, len(gapSet))
	for g := range gapSet {
		gapList = append(gapList, g)
	}
	sort.Strings(gapList)
	if len(gapList) > 6 {
		gapList = gapList[:6]
	}

	headline := ReasoningItem{}
	maxConf := -1.0
	for _, res := range r.Reasoning.Results {
		if !res.Feasible {
			continue
		}
		if res.Confidence > maxConf {
			maxConf = res.Confidence
			headline = ReasoningItem{
				ID:         res.RuleID,
				Title:      res.Name,
				Verdict:    verdictFromResult(res.Feasible, res.PrecondOK),
				Confidence: res.Confidence,
				Summary:    res.Explanation,
				Evidence:   summarizeEvidence(res.SupportingEventIDs),
				Gaps:       summarizeGaps(res.MissingEvidence),
				NextMoves:  r.NextMoves,
				Updated:    latestTimestamp(r.GeneratedAt),
			}
		}
	}

	suggested := []string{}
	for _, move := range r.NextMoves {
		suggested = append(suggested, move)
	}
	if len(suggested) == 0 {
		for i, gap := range gapList {
			if i >= 2 {
				break
			}
			suggested = append(suggested, "Collect evidence: "+gap)
		}
	}

	governanceHolds := 0
	for _, ticket := range r.Reasoning.Tickets {
		if strings.EqualFold(ticket.Status, "in_review") {
			governanceHolds++
		}
	}

	return OverviewResponse{
		Kpis: []KpiItem{
			{Label: "Active Threads", Value: fmt.Sprintf("%d", len(r.Reasoning.Threads)), Sub: "Last 24h"},
			{Label: "Feasible Findings", Value: fmt.Sprintf("%d", feasibleCount), Sub: "Requires review"},
			{Label: "Evidence Gaps", Value: fmt.Sprintf("%d", len(gapSet)), Sub: "Tracked"},
			{Label: "Governance Holds", Value: fmt.Sprintf("%d", governanceHolds), Sub: "Awaiting sign"},
		},
		Headline:         headline,
		EvidenceGaps:     gapList,
		DriftSignals:     r.DriftSignals,
		SuggestedActions: suggested,
	}
}

func buildReasoningItems(r *reportFile) []ReasoningItem {
	items := make([]ReasoningItem, 0, len(r.Reasoning.Results))
	for _, res := range r.Reasoning.Results {
		items = append(items, ReasoningItem{
			ID:         res.RuleID,
			Title:      res.Name,
			Verdict:    verdictFromResult(res.Feasible, res.PrecondOK),
			Confidence: res.Confidence,
			Summary:    res.Explanation,
			Evidence:   summarizeEvidence(res.SupportingEventIDs),
			Gaps:       summarizeGaps(res.MissingEvidence),
			NextMoves:  r.NextMoves,
			Updated:    latestTimestamp(r.GeneratedAt),
		})
	}
	return items
}

func buildQueueItems(r *reportFile) []QueueItem {
	items := []QueueItem{}
	resultMap := map[string]reportFileReasoningResult{}
	for _, res := range r.Reasoning.Results {
		resultMap[res.RuleID] = res
	}
	for _, ticket := range r.Reasoning.Tickets {
		ruleTitle := ""
		var matched reportFileReasoningResult
		if len(ticket.RuleIDs) > 0 {
			ruleID := ticket.RuleIDs[0]
			if res, ok := resultMap[ruleID]; ok {
				matched = res
				ruleTitle = res.Name
			} else {
				ruleTitle = ruleID
			}
		}
		verdict := "INCOMPLETE"
		if ticket.DecisionLabel == "escalate" {
			verdict = "POSSIBLE"
		}
		if ticket.DecisionLabel == "keep" {
			verdict = "INCOMPLETE"
		}
		if ticket.DecisionLabel == "suppress" {
			verdict = "IMPOSSIBLE"
		}
		items = append(items, QueueItem{
			ID:         ticket.ID,
			Rule:       ruleTitle,
			Verdict:    verdict,
			Confidence: matched.Confidence,
			Evidence:   summarizeEvidence(matched.SupportingEventIDs),
			Gaps:       summarizeGaps(matched.MissingEvidence),
			Principal:  ticket.Principal,
			Asset:      ticket.Host,
			Updated:    latestTimestamp(ticket.UpdatedAt),
		})
	}
	return items
}

func buildGraph(r *reportFile) GraphResponse {
	threads := make([]ThreadItem, 0, len(r.Reasoning.Threads))
	for _, t := range r.Reasoning.Threads {
		threads = append(threads, ThreadItem{
			ID:         t.ID,
			Host:       t.Host,
			Principal:  t.Principal,
			RuleIDs:    t.RuleIDs,
			Confidence: t.Confidence,
			Reason:     t.Reason,
		})
	}
	return GraphResponse{Threads: threads}
}

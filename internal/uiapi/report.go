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
	State       struct {
		ReachableHosts      map[string]bool `json:"reachable_hosts"`
		ReachableIdentities map[string]bool `json:"reachable_identities"`
		CompromisedHosts    map[string]bool `json:"compromised_hosts"`
		CompromisedUsers    map[string]bool `json:"compromised_users"`
		Progression         []struct {
			Time       string  `json:"time"`
			Source     string  `json:"source"`
			Principal  string  `json:"principal"`
			Asset      string  `json:"asset"`
			Action     string  `json:"action"`
			Confidence float64 `json:"confidence"`
			Stage      string  `json:"stage"`
			Rationale  string  `json:"rationale"`
		} `json:"progression"`
	} `json:"state"`
	Reasoning struct {
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
	RuleID            string  `json:"rule_id"`
	Name              string  `json:"name"`
	Feasible          bool    `json:"feasible"`
	PrecondOK         bool    `json:"precond_ok"`
	Conflicted        bool    `json:"conflicted"`
	PolicyImpossible  bool    `json:"policy_impossible"`
	Confidence        float64 `json:"confidence"`
	ConfidenceFactors *struct {
		Coverage            float64 `json:"coverage"`
		Recency             float64 `json:"recency"`
		Corroboration       float64 `json:"corroboration"`
		EvidencePresent     int     `json:"evidence_present"`
		EvidenceTotal       int     `json:"evidence_total"`
		SupportingEvents    int     `json:"supporting_events"`
		MissingEvidence     int     `json:"missing_evidence"`
		CoverageWeight      float64 `json:"coverage_weight"`
		RecencyWeight       float64 `json:"recency_weight"`
		CorroborationWeight float64 `json:"corroboration_weight"`
		RawScore            float64 `json:"raw_score"`
		Floor               float64 `json:"floor"`
		Ceiling             float64 `json:"ceiling"`
	} `json:"confidence_factors,omitempty"`
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

func verdictFromResult(feasible bool, precondOK bool, reasonCode string) string {
	if feasible {
		return "POSSIBLE"
	}
	if reasonCode == "telemetry_gap_high_signal" {
		return "INCOMPLETE"
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
				ID:                res.RuleID,
				Title:             res.Name,
				Verdict:           verdictFromResult(res.Feasible, res.PrecondOK, res.ReasonCode),
				Confidence:        res.Confidence,
				ConfidenceFactors: mapConfidenceFactors(res.ConfidenceFactors),
				Summary:           res.Explanation,
				Evidence:          summarizeEvidence(res.SupportingEventIDs),
				Gaps:              summarizeGaps(res.MissingEvidence),
				NextMoves:         r.NextMoves,
				Updated:           latestTimestamp(r.GeneratedAt),
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
			ID:                res.RuleID,
			Title:             res.Name,
			Verdict:           verdictFromResult(res.Feasible, res.PrecondOK, res.ReasonCode),
			Confidence:        res.Confidence,
			ConfidenceFactors: mapConfidenceFactors(res.ConfidenceFactors),
			Summary:           res.Explanation,
			Evidence:          summarizeEvidence(res.SupportingEventIDs),
			Gaps:              summarizeGaps(res.MissingEvidence),
			NextMoves:         r.NextMoves,
			Updated:           latestTimestamp(r.GeneratedAt),
		})
	}
	return items
}

func mapConfidenceFactors(in *struct {
	Coverage            float64 `json:"coverage"`
	Recency             float64 `json:"recency"`
	Corroboration       float64 `json:"corroboration"`
	EvidencePresent     int     `json:"evidence_present"`
	EvidenceTotal       int     `json:"evidence_total"`
	SupportingEvents    int     `json:"supporting_events"`
	MissingEvidence     int     `json:"missing_evidence"`
	CoverageWeight      float64 `json:"coverage_weight"`
	RecencyWeight       float64 `json:"recency_weight"`
	CorroborationWeight float64 `json:"corroboration_weight"`
	RawScore            float64 `json:"raw_score"`
	Floor               float64 `json:"floor"`
	Ceiling             float64 `json:"ceiling"`
}) *ConfidenceFactors {
	if in == nil {
		return nil
	}
	return &ConfidenceFactors{
		Coverage:            in.Coverage,
		Recency:             in.Recency,
		Corroboration:       in.Corroboration,
		EvidencePresent:     in.EvidencePresent,
		EvidenceTotal:       in.EvidenceTotal,
		SupportingEvents:    in.SupportingEvents,
		MissingEvidence:     in.MissingEvidence,
		CoverageWeight:      in.CoverageWeight,
		RecencyWeight:       in.RecencyWeight,
		CorroborationWeight: in.CorroborationWeight,
		RawScore:            in.RawScore,
		Floor:               in.Floor,
		Ceiling:             in.Ceiling,
	}
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
	nodes := map[string]GraphNode{}
	edges := []GraphEdge{}
	compHosts := []string{}
	compUsers := []string{}

	addNode := func(kind string, label string, status string) string {
		id := kind + ":" + label
		if _, ok := nodes[id]; !ok {
			nodes[id] = GraphNode{
				ID:     id,
				Label:  label,
				Kind:   kind,
				Status: status,
			}
		}
		return id
	}

	for host := range r.State.CompromisedHosts {
		compHosts = append(compHosts, addNode("host", host, "compromised"))
	}
	for host := range r.State.ReachableHosts {
		if r.State.CompromisedHosts[host] {
			continue
		}
		addNode("host", host, "reachable")
	}
	for user := range r.State.CompromisedUsers {
		compUsers = append(compUsers, addNode("identity", user, "compromised"))
	}
	for user := range r.State.ReachableIdentities {
		if r.State.CompromisedUsers[user] {
			continue
		}
		addNode("identity", user, "reachable")
	}

	if len(compHosts) > 0 {
		for id, node := range nodes {
			if node.Kind == "host" && node.Status == "reachable" {
				edges = append(edges, GraphEdge{
					From:   compHosts[0],
					To:     id,
					Label:  "reachable",
					Status: "incomplete",
				})
			}
		}
	}
	if len(compUsers) > 0 {
		for id, node := range nodes {
			if node.Kind == "identity" && node.Status == "reachable" {
				edges = append(edges, GraphEdge{
					From:   compUsers[0],
					To:     id,
					Label:  "reachable",
					Status: "incomplete",
				})
			}
		}
	}

	progression := make([]ProgressionItem, 0, len(r.State.Progression))
	for _, p := range r.State.Progression {
		progression = append(progression, ProgressionItem{
			Time:       latestTimestamp(p.Time),
			Stage:      p.Stage,
			Action:     p.Action,
			Principal:  p.Principal,
			Asset:      p.Asset,
			Confidence: p.Confidence,
			Rationale:  p.Rationale,
		})
	}

	nodeList := make([]GraphNode, 0, len(nodes))
	for _, n := range nodes {
		nodeList = append(nodeList, n)
	}
	sort.Slice(nodeList, func(i, j int) bool { return nodeList[i].ID < nodeList[j].ID })

	return GraphResponse{Threads: threads, Nodes: nodeList, Edges: edges, Progression: progression}
}

func buildPilotKpis(r *reportFile) PilotKpisResponse {
	total := len(r.Reasoning.Results)
	feasible := 0
	incomplete := 0
	impossible := 0
	conflicted := 0
	policyBlocked := 0
	escalate := 0
	suppress := 0
	keep := 0
	deprioritize := 0
	confSum := 0.0
	confCount := 0

	reasonCounts := map[string]int{}
	gapCounts := map[string]int{}
	ruleCounts := map[string]int{}

	for _, res := range r.Reasoning.Results {
		if res.PolicyImpossible {
			policyBlocked++
		}
		if res.Conflicted {
			conflicted++
		}
		if res.Feasible {
			feasible++
			confSum += res.Confidence
			confCount++
		}
		if len(res.MissingEvidence) > 0 {
			incomplete++
		} else if !res.Feasible && !res.Conflicted && !res.PolicyImpossible {
			impossible++
		}
		switch strings.ToLower(strings.TrimSpace(res.DecisionLabel)) {
		case "escalate":
			escalate++
		case "suppress":
			suppress++
		case "keep":
			keep++
		case "deprioritize":
			deprioritize++
		}
		if res.ReasonCode != "" {
			reasonCounts[res.ReasonCode]++
		}
		if res.RuleID != "" {
			ruleCounts[res.RuleID]++
		}
		for _, gap := range res.MissingEvidence {
			label := gap.Description
			if label == "" {
				label = gap.Type
			}
			if label != "" {
				gapCounts[label]++
			}
		}
	}

	topReasons := topCounts(reasonCounts, 8)
	topGaps := topCounts(gapCounts, 8)
	topRules := topCounts(ruleCounts, 8)

	avgConf := 0.0
	if confCount > 0 {
		avgConf = confSum / float64(confCount)
	}

	return PilotKpisResponse{
		GeneratedAt:      latestTimestamp(r.GeneratedAt),
		TotalResults:     total,
		Feasible:         feasible,
		Incomplete:       incomplete,
		Impossible:       impossible,
		Conflicted:       conflicted,
		PolicyBlocked:    policyBlocked,
		Escalate:         escalate,
		Suppress:         suppress,
		Keep:             keep,
		Deprioritize:     deprioritize,
		AvgConfidence:    avgConf,
		TopReasonCodes:   topReasons,
		TopEvidenceGaps:  topGaps,
		TopDecisionRules: topRules,
	}
}

func topCounts(in map[string]int, limit int) []CountItem {
	if len(in) == 0 {
		return []CountItem{}
	}
	out := make([]CountItem, 0, len(in))
	for k, v := range in {
		out = append(out, CountItem{Label: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].Label < out[j].Label
		}
		return out[i].Count > out[j].Count
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

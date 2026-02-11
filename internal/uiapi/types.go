package uiapi

type OverviewResponse struct {
	Kpis             []KpiItem     `json:"kpis"`
	Headline         ReasoningItem `json:"headline"`
	EvidenceGaps     []string      `json:"evidence_gaps"`
	DriftSignals     []string      `json:"drift_signals"`
	SuggestedActions []string      `json:"suggested_actions"`
}

type KpiItem struct {
	Label string `json:"label"`
	Value string `json:"value"`
	Sub   string `json:"sub"`
}

type ReasoningItem struct {
	ID         string   `json:"id"`
	Title      string   `json:"title"`
	Verdict    string   `json:"verdict"`
	Confidence float64  `json:"confidence"`
	Summary    string   `json:"summary"`
	Evidence   []string `json:"evidence"`
	Gaps       []string `json:"gaps"`
	NextMoves  []string `json:"next_moves"`
	Updated    string   `json:"updated"`
}

type QueueItem struct {
	ID         string   `json:"id"`
	Rule       string   `json:"rule"`
	Verdict    string   `json:"verdict"`
	Confidence float64  `json:"confidence"`
	Evidence   []string `json:"evidence"`
	Gaps       []string `json:"gaps"`
	Principal  string   `json:"principal"`
	Asset      string   `json:"asset"`
	Updated    string   `json:"updated"`
}

type ApprovalItem struct {
	ID       string `json:"id"`
	Scope    string `json:"scope"`
	Status   string `json:"status"`
	Approver string `json:"approver"`
	Expires  string `json:"expires"`
}

type AuditItem struct {
	ID        string `json:"id"`
	Timestamp string `json:"timestamp"`
	Summary   string `json:"summary"`
	Signer    string `json:"signer"`
}

type EvaluationItem struct {
	Label string `json:"label"`
	Value string `json:"value"`
	Delta string `json:"delta"`
	Note  string `json:"note"`
}

type GraphResponse struct {
	Threads []ThreadItem `json:"threads"`
}

type ThreadItem struct {
	ID         string   `json:"id"`
	Host       string   `json:"host"`
	Principal  string   `json:"principal"`
	RuleIDs    []string `json:"rule_ids"`
	Confidence float64  `json:"confidence"`
	Reason     string   `json:"reason"`
}

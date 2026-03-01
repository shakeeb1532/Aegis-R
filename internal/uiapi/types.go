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
	ID                string             `json:"id"`
	Title             string             `json:"title"`
	Verdict           string             `json:"verdict"`
	Confidence        float64            `json:"confidence"`
	ConfidenceFactors *ConfidenceFactors `json:"confidence_factors,omitempty"`
	Summary           string             `json:"summary"`
	Evidence          []string           `json:"evidence"`
	Gaps              []string           `json:"gaps"`
	NextMoves         []string           `json:"next_moves"`
	Updated           string             `json:"updated"`
}

type ConfidenceFactors struct {
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
	ID            string   `json:"id"`
	Scope         string   `json:"scope"`
	Status        string   `json:"status"`
	Approver      string   `json:"approver"`
	Approvers     []string `json:"approvers,omitempty"`
	Expires       string   `json:"expires"`
	DualRequired  int      `json:"dual_required"`
	ValidSigners  int      `json:"valid_signers"`
	DualApproved  bool     `json:"dual_approved"`
	OktaVerified  bool     `json:"okta_verified"`
	HumanDecision string   `json:"human_decision"`
	TemplateID    string   `json:"template_id,omitempty"`
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
	Threads     []ThreadItem      `json:"threads"`
	Nodes       []GraphNode       `json:"nodes"`
	Edges       []GraphEdge       `json:"edges"`
	Progression []ProgressionItem `json:"progression"`
}

type ThreadItem struct {
	ID         string   `json:"id"`
	Host       string   `json:"host"`
	Principal  string   `json:"principal"`
	RuleIDs    []string `json:"rule_ids"`
	Confidence float64  `json:"confidence"`
	Reason     string   `json:"reason"`
}

type GraphNode struct {
	ID     string `json:"id"`
	Label  string `json:"label"`
	Kind   string `json:"kind"`
	Status string `json:"status"`
}

type GraphEdge struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Label  string `json:"label"`
	Status string `json:"status"`
}

type ProgressionItem struct {
	Time       string  `json:"time"`
	Stage      string  `json:"stage"`
	Action     string  `json:"action"`
	Principal  string  `json:"principal"`
	Asset      string  `json:"asset"`
	Confidence float64 `json:"confidence"`
	Rationale  string  `json:"rationale"`
}

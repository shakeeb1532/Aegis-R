package model

import "time"

type Event struct {
	ID      string                 `json:"id"`
	Time    time.Time              `json:"time"`
	Host    string                 `json:"host"`
	User    string                 `json:"user"`
	Type    string                 `json:"type"`
	Details map[string]interface{} `json:"details"`
}

type Envelope struct {
	Timestamp  time.Time `json:"timestamp"`
	Source     string    `json:"source"`
	Principal  string    `json:"principal"`
	Asset      string    `json:"asset"`
	Action     string    `json:"action"`
	Evidence   []string  `json:"evidence"`
	Confidence float64   `json:"confidence"`
	Tags       []string  `json:"tags"`
}

type EvidenceRequirement struct {
	Type        string `json:"type"`
	Description string `json:"description"`
}

type RuleResult struct {
	RuleID             string                `json:"rule_id"`
	Name               string                `json:"name"`
	Feasible           bool                  `json:"feasible"`
	PrecondOK          bool                  `json:"precond_ok"`
	Confidence         float64               `json:"confidence"`
	MissingEvidence    []EvidenceRequirement `json:"missing_evidence"`
	SupportingEvents   []Event               `json:"supporting_events"`
	SupportingEventIDs []string              `json:"supporting_event_ids"`
	Explanation        string                `json:"explanation"`
	GapNarrative       string                `json:"gap_narrative"`
	ReasonCode         string                `json:"reason_code"`
	DecisionLabel      string                `json:"decision_label"`
	CacheHit           bool                  `json:"cache_hit"`
	ThreadID           string                `json:"thread_id"`
	ThreadConfidence   float64               `json:"thread_confidence"`
	ThreadReason       string                `json:"thread_reason"`
}

type ReasoningReport struct {
	GeneratedAt     time.Time    `json:"generated_at"`
	Summary         string       `json:"summary"`
	Results         []RuleResult `json:"results"`
	Narrative       []string     `json:"narrative"`
	ConfidenceModel string       `json:"confidence_model"`
	ConfidenceNote  string       `json:"confidence_note"`
}

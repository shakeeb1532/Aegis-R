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
	Conflicted         bool                  `json:"conflicted,omitempty"`
	PolicyImpossible   bool                  `json:"policy_impossible,omitempty"`
	PolicyReason       string                `json:"policy_reason,omitempty"`
	PrecondOK          bool                  `json:"precond_ok"`
	Confidence         float64               `json:"confidence"`
	MissingEvidence    []EvidenceRequirement `json:"missing_evidence"`
	SupportingEvents   []Event               `json:"supporting_events"`
	SupportingEventIDs []string              `json:"supporting_event_ids"`
	Explanation        string                `json:"explanation"`
	GapNarrative       string                `json:"gap_narrative"`
	ReasonCode         string                `json:"reason_code"`
	CausalBlockers     []string              `json:"causal_blockers,omitempty"`
	CausalError        string                `json:"causal_error,omitempty"`
	NecessaryCauses    []string              `json:"necessary_causes,omitempty"`
	NecessaryCauseSets [][]string            `json:"necessary_cause_sets,omitempty"`
	DecisionLabel      string                `json:"decision_label"`
	CacheHit           bool                  `json:"cache_hit"`
	ThreadID           string                `json:"thread_id"`
	ThreadConfidence   float64               `json:"thread_confidence"`
	ThreadReason       string                `json:"thread_reason"`
	LikelihoodScore    float64               `json:"likelihood_score,omitempty"`
	LikelihoodSource   string                `json:"likelihood_source,omitempty"`
}

type ReasoningReport struct {
	GeneratedAt          time.Time         `json:"generated_at"`
	Summary              string            `json:"summary"`
	Results              []RuleResult      `json:"results"`
	Narrative            []string          `json:"narrative"`
	ConfidenceModel      string            `json:"confidence_model"`
	ConfidenceNote       string            `json:"confidence_note"`
	Explanation          string            `json:"explanation,omitempty"`
	SuggestedSteps       []string          `json:"suggested_steps,omitempty"`
	ExplanationSource    string            `json:"explanation_source,omitempty"`
	RecommendedTelemetry []string          `json:"recommended_telemetry,omitempty"`
	TelemetrySource      string            `json:"telemetry_source,omitempty"`
	SimilarIncidents     []SimilarIncident `json:"similar_incidents,omitempty"`
	SuggestedPlaybooks   []string          `json:"suggested_playbooks,omitempty"`
	MLAssistEnabled      bool              `json:"ml_assist_enabled,omitempty"`
	MLAssistNotes        []string          `json:"ml_assist_notes,omitempty"`
	AIOverlay            AIOverlaySummary  `json:"ai_overlay,omitempty"`
	AIAlerts             []AIAlert         `json:"ai_alerts,omitempty"`
}

type SimilarIncident struct {
	ID       string   `json:"id"`
	Summary  string   `json:"summary"`
	RuleIDs  []string `json:"rule_ids"`
	Score    float64  `json:"score"`
	Playbook string   `json:"playbook"`
}

type AIOverlaySummary struct {
	Enabled         bool     `json:"enabled,omitempty"`
	Mode            string   `json:"mode,omitempty"`
	CandidateCount  int      `json:"candidate_count,omitempty"`
	EscalatedCount  int      `json:"escalated_count,omitempty"`
	TriagedCount    int      `json:"triaged_count,omitempty"`
	SuppressedCount int      `json:"suppressed_count,omitempty"`
	Threshold       float64  `json:"threshold,omitempty"`
	Notes           []string `json:"notes,omitempty"`
}

type AIAlert struct {
	RuleID       string  `json:"rule_id"`
	Name         string  `json:"name"`
	Sensitivity  float64 `json:"sensitivity"`
	EvidenceHits int     `json:"evidence_hits"`
	Status       string  `json:"status"`
	Reason       string  `json:"reason"`
}

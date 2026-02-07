package state

import (
	"encoding/json"
	"os"
	"time"

	"aegisr/internal/ops"
)

type AttackState struct {
	UpdatedAt           time.Time       `json:"updated_at"`
	CompromisedHosts    map[string]bool `json:"compromised_hosts"`
	CompromisedUsers    map[string]bool `json:"compromised_users"`
	ReachableHosts      map[string]bool `json:"reachable_hosts"`
	ReachableIdentities map[string]bool `json:"reachable_identities"`
	Signals             []string        `json:"signals"`
	ReasoningChain      []string        `json:"reasoning_chain"`
	Progression         []ProgressEvent `json:"progression"`
	Position            Position        `json:"position"`
	GraphOverlay        GraphOverlay    `json:"graph_overlay"`
	DecisionCache       DecisionCache   `json:"decision_cache"`
	Threads             []Thread        `json:"threads"`
	Tickets             []Ticket        `json:"tickets"`
}

type ProgressEvent struct {
	Time       time.Time `json:"time"`
	Source     string    `json:"source"`
	Principal  string    `json:"principal"`
	Asset      string    `json:"asset"`
	Action     string    `json:"action"`
	Confidence float64   `json:"confidence"`
	Stage      string    `json:"stage"`
	Rationale  string    `json:"rationale"`
}

func (p *ProgressEvent) GetTime() time.Time {
	return p.Time
}

func (p *ProgressEvent) GetConfidence() float64 {
	return p.Confidence
}

func (p *ProgressEvent) SetConfidence(v float64) {
	p.Confidence = v
}

type Position struct {
	Stage      string   `json:"stage"`
	Principals []string `json:"principals"`
	Assets     []string `json:"assets"`
}

type GraphOverlay struct {
	CurrentNodes []string `json:"current_nodes"`
	Reachable    []string `json:"reachable_nodes"`
}

type DecisionCache map[string]DecisionCacheEntry

type DecisionCacheEntry struct {
	Host        string    `json:"host"`
	Principal   string    `json:"principal"`
	RuleID      string    `json:"rule_id"`
	Verdict     string    `json:"verdict"`
	Label       string    `json:"label"`
	ReasonCode  string    `json:"reason_code"`
	UpdatedAt   time.Time `json:"updated_at"`
	EvidenceIDs []string  `json:"evidence_ids"`
}

type Thread struct {
	ID         string    `json:"id"`
	Host       string    `json:"host"`
	Principal  string    `json:"principal"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	RuleIDs    []string  `json:"rule_ids"`
	Confidence float64   `json:"confidence"`
	Reason     string    `json:"reason"`
}

type Ticket struct {
	ID            string    `json:"id"`
	ThreadID      string    `json:"thread_id"`
	Host          string    `json:"host"`
	Principal     string    `json:"principal"`
	Status        string    `json:"status"`
	DecisionLabel string    `json:"decision_label"`
	ReasonCode    string    `json:"reason_code"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	RuleIDs       []string  `json:"rule_ids"`
}

func New() AttackState {
	return AttackState{
		UpdatedAt:           time.Now().UTC(),
		CompromisedHosts:    map[string]bool{},
		CompromisedUsers:    map[string]bool{},
		ReachableHosts:      map[string]bool{},
		ReachableIdentities: map[string]bool{},
		Signals:             []string{},
		ReasoningChain:      []string{},
		Progression:         []ProgressEvent{},
		GraphOverlay:        GraphOverlay{},
		DecisionCache:       DecisionCache{},
		Threads:             []Thread{},
		Tickets:             []Ticket{},
	}
}

func Load(path string) (AttackState, error) {
	if path == "" {
		return New(), nil
	}
	if !ops.IsSafePath(path) {
		return New(), os.ErrInvalid
	}
	//nolint:gosec // path validated via IsSafePath
	data, err := os.ReadFile(path)
	if err != nil {
		return New(), err
	}
	var s AttackState
	if err := json.Unmarshal(data, &s); err != nil {
		return New(), err
	}
	if s.CompromisedHosts == nil {
		s.CompromisedHosts = map[string]bool{}
	}
	if s.CompromisedUsers == nil {
		s.CompromisedUsers = map[string]bool{}
	}
	if s.ReachableHosts == nil {
		s.ReachableHosts = map[string]bool{}
	}
	if s.ReachableIdentities == nil {
		s.ReachableIdentities = map[string]bool{}
	}
	if s.Progression == nil {
		s.Progression = []ProgressEvent{}
	}
	if s.DecisionCache == nil {
		s.DecisionCache = DecisionCache{}
	}
	if s.Threads == nil {
		s.Threads = []Thread{}
	}
	if s.Tickets == nil {
		s.Tickets = []Ticket{}
	}
	return s, nil
}

func Save(path string, s AttackState) error {
	if path == "" {
		return nil
	}
	if !ops.IsSafePath(path) {
		return os.ErrInvalid
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

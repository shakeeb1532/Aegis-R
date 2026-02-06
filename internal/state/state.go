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
	}
}

func Load(path string) (AttackState, error) {
	if path == "" {
		return New(), nil
	}
	if !ops.IsSafePath(path) {
		return New(), os.ErrInvalid
	}
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

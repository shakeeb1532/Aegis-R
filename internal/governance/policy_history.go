package governance

import (
	"encoding/json"
	"errors"
	"os"
	"time"

	"aegisr/internal/ops"
)

type PolicyConflictError struct {
	ActiveIDs []string
}

func (e PolicyConflictError) Error() string {
	return "policy conflict: multiple active policies"
}

func LoadHistory(path string) ([]Policy, error) {
	if path == "" {
		return nil, os.ErrInvalid
	}
	if !ops.IsSafePath(path) {
		return nil, os.ErrInvalid
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var policies []Policy
	if err := json.Unmarshal(data, &policies); err != nil {
		return nil, err
	}
	for i := range policies {
		if policies[i].Version == "" {
			policies[i].Version = "v1"
		}
		if policies[i].ActiveFrom == "" {
			policies[i].ActiveFrom = policies[i].UpdatedAt
		}
		if policies[i].MinApprovals <= 0 {
			policies[i].MinApprovals = 2
		}
	}
	return policies, nil
}

func ResolveActive(policies []Policy, now time.Time) (Policy, error) {
	if len(policies) == 0 {
		return Policy{}, errors.New("no policies supplied")
	}
	active := []Policy{}
	for _, p := range policies {
		if p.ActiveFrom == "" {
			p.ActiveFrom = p.UpdatedAt
		}
		t, err := time.Parse(time.RFC3339, p.ActiveFrom)
		if err != nil {
			return Policy{}, err
		}
		if !t.After(now) {
			active = append(active, p)
		}
	}
	if len(active) == 0 {
		return Policy{}, errors.New("no active policy for current time")
	}
	superseded := map[string]bool{}
	for _, p := range active {
		for _, id := range p.Supersedes {
			superseded[id] = true
		}
	}
	final := []Policy{}
	for _, p := range active {
		if superseded[p.ID] {
			continue
		}
		final = append(final, p)
	}
	if len(final) == 0 {
		return Policy{}, errors.New("all active policies superseded")
	}
	if len(final) > 1 {
		ids := make([]string, 0, len(final))
		for _, p := range final {
			ids = append(ids, p.ID)
		}
		return Policy{}, PolicyConflictError{ActiveIDs: ids}
	}
	return final[0], nil
}

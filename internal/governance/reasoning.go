package governance

import (
	"encoding/json"
	"os"
	"time"

	"aegisr/internal/ops"
)

type AnalystProfile struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Specialties []string `json:"specialties"`
	Notes       string   `json:"notes"`
}

type ReasoningConstraint struct {
	ID              string   `json:"id"`
	RuleID          string   `json:"rule_id"`
	RequireEvidence []string `json:"require_evidence"`
	ForbidEvidence  []string `json:"forbid_evidence"`
	Author          string   `json:"author"`
	CreatedAt       string   `json:"created_at"`
	Notes           string   `json:"notes"`
}

type Disagreement struct {
	At        string `json:"at"`
	AnalystID string `json:"analyst_id"`
	RuleID    string `json:"rule_id"`
	Expected  string `json:"expected"`
	Actual    string `json:"actual"`
	Rationale string `json:"rationale"`
}

func LoadProfiles(path string) ([]AnalystProfile, error) {
	if path == "" {
		return nil, nil
	}
	if !ops.IsSafePath(path) {
		return nil, os.ErrInvalid
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []AnalystProfile
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func SaveProfiles(path string, profiles []AnalystProfile) error {
	if !ops.IsSafePath(path) {
		return os.ErrInvalid
	}
	data, err := json.MarshalIndent(profiles, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func LoadConstraints(path string) ([]ReasoningConstraint, error) {
	if path == "" {
		return nil, nil
	}
	if !ops.IsSafePath(path) {
		return nil, os.ErrInvalid
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []ReasoningConstraint
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func SaveConstraints(path string, cons []ReasoningConstraint) error {
	if !ops.IsSafePath(path) {
		return os.ErrInvalid
	}
	data, err := json.MarshalIndent(cons, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func AppendDisagreement(path string, d Disagreement) error {
	if !ops.IsSafePath(path) {
		return os.ErrInvalid
	}
	if d.At == "" {
		d.At = time.Now().UTC().Format(time.RFC3339)
	}
	data, err := json.Marshal(d)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(data)
	return err
}

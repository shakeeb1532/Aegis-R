package ui

import (
	"encoding/json"
	"os"
	"strings"

	"aegisr/internal/audit"
	"aegisr/internal/ops"
)

type SignedStatus struct {
	ID     string
	Signer string
	Status string
}

func loadSignedArtifacts(path string) ([]SignedStatus, error) {
	if path == "" {
		return nil, nil
	}
	if !ops.IsSafePath(path) {
		return nil, os.ErrInvalid
	}
	//nolint:gosec // path validated via IsSafePath
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	out := []SignedStatus{}
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var s audit.SignedArtifact
		if err := json.Unmarshal([]byte(line), &s); err != nil {
			continue
		}
		status := "valid"
		if err := audit.VerifySignedArtifact(s); err != nil {
			status = "invalid"
		}
		out = append(out, SignedStatus{ID: s.Artifact.ID, Signer: s.SignerID, Status: status})
	}
	return out, nil
}

func filterSigned(list []SignedStatus, q string) []SignedStatus {
	if q == "" {
		return list
	}
	q = strings.ToLower(q)
	out := []SignedStatus{}
	for _, s := range list {
		if strings.Contains(strings.ToLower(s.ID), q) || strings.Contains(strings.ToLower(s.Signer), q) || strings.Contains(strings.ToLower(s.Status), q) {
			out = append(out, s)
		}
	}
	return out
}

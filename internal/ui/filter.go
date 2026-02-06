package ui

import (
	"strings"

	"aegisr/internal/approval"
	"aegisr/internal/audit"
)

func filterArtifacts(list []audit.Artifact, q string) []audit.Artifact {
	if q == "" {
		return list
	}
	q = strings.ToLower(q)
	out := []audit.Artifact{}
	for _, a := range list {
		if strings.Contains(strings.ToLower(a.ID), q) || strings.Contains(strings.ToLower(a.Summary), q) {
			out = append(out, a)
		}
	}
	return out
}

func filterApprovals(list []approval.Approval, q string) []approval.Approval {
	if q == "" {
		return list
	}
	q = strings.ToLower(q)
	out := []approval.Approval{}
	for _, a := range list {
		if strings.Contains(strings.ToLower(a.ID), q) || strings.Contains(strings.ToLower(a.SignerID), q) || strings.Contains(strings.ToLower(a.SignerRole), q) {
			out = append(out, a)
		}
	}
	return out
}

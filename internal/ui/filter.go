package ui

import (
	"strings"

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

func filterApprovals(list []ApprovalRecord, q string) []ApprovalRecord {
	if q == "" {
		return list
	}
	q = strings.ToLower(q)
	out := []ApprovalRecord{}
	for _, a := range list {
		if strings.Contains(strings.ToLower(a.Approval.ID), q) || strings.Contains(strings.ToLower(a.Approval.SignerID), q) || strings.Contains(strings.ToLower(a.Approval.SignerRole), q) || strings.Contains(strings.ToLower(a.Rationale), q) {
			out = append(out, a)
		}
	}
	return out
}

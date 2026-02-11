package ui

import (
	"encoding/json"
	"os"
	"strings"
	"time"

	"aegisr/internal/approval"
	"aegisr/internal/ops"
)

type ApprovalRecord struct {
	Approval     approval.Approval `json:"approval"`
	Rationale    string            `json:"rationale"`
	EvidenceGaps []string          `json:"evidence_gaps"`
	CreatedAt    string            `json:"created_at"`
}

func loadApprovals(path string) ([]ApprovalRecord, error) {
	if path == "" {
		return nil, nil
	}
	if !ops.IsSafePath(path) {
		return nil, os.ErrInvalid
	}
	//nolint:gosec // path validated via IsSafePath
	// #nosec G304
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	out := []ApprovalRecord{}
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var rec ApprovalRecord
		if err := json.Unmarshal([]byte(line), &rec); err == nil && rec.Approval.ID != "" {
			out = append(out, rec)
			continue
		}
		var a approval.Approval
		if err := json.Unmarshal([]byte(line), &a); err != nil {
			continue
		}
		out = append(out, ApprovalRecord{Approval: a})
	}
	return out, nil
}

func appendApproval(path string, rec ApprovalRecord) error {
	if !ops.IsSafePath(path) {
		return os.ErrInvalid
	}
	if rec.CreatedAt == "" {
		rec.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	//nolint:gosec // path validated via IsSafePath
	// #nosec G304
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	_, err = f.Write(data)
	return err
}

package ui

import (
	"encoding/json"
	"os"
	"strings"

	"aegisr/internal/approval"
	"aegisr/internal/ops"
)

func loadApprovals(path string) ([]approval.Approval, error) {
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
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	out := []approval.Approval{}
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var a approval.Approval
		if err := json.Unmarshal([]byte(line), &a); err != nil {
			continue
		}
		out = append(out, a)
	}
	return out, nil
}

func appendApproval(path string, a approval.Approval) error {
	if !ops.IsSafePath(path) {
		return os.ErrInvalid
	}
	data, err := json.Marshal(a)
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

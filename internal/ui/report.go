package ui

import (
	"encoding/json"
	"os"

	"aegisr/internal/model"
	"aegisr/internal/ops"
)

func loadReasoningReport(path string) (model.ReasoningReport, error) {
	var r model.ReasoningReport
	if path == "" {
		return r, nil
	}
	if !ops.IsSafePath(path) {
		return r, os.ErrInvalid
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return r, err
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return r, err
	}
	return r, nil
}

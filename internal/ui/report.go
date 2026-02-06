package ui

import (
	"encoding/json"
	"os"

	"aegisr/internal/model"
)

func loadReasoningReport(path string) (model.ReasoningReport, error) {
	var r model.ReasoningReport
	if path == "" {
		return r, nil
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

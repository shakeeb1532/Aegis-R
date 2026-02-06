package integration

import (
	"encoding/json"
	"fmt"
	"os"

	"aegisr/internal/core"
)

type SIEMPayload struct {
	Vendor   string            `json:"vendor"`
	Type     string            `json:"type"`
	Summary  string            `json:"summary"`
	Findings []string          `json:"findings"`
	Next     []string          `json:"next_moves"`
	Tags     map[string]string `json:"tags"`
}

func ExportSIEM(path string, out core.Output) error {
	if path == "" {
		return nil
	}
	payload := SIEMPayload{
		Vendor:   "Aegis-R",
		Type:     "reasoning_report",
		Summary:  out.Summary,
		Findings: out.Findings,
		Next:     out.NextMoves,
		Tags: map[string]string{
			"generated_at": out.GeneratedAt.Format("2006-01-02T15:04:05Z"),
		},
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return err
	}
	fmt.Printf("SIEM export written: %s\n", path)
	return nil
}

package ui

import (
	"encoding/json"
	"os"
	"time"

	"aegisr/internal/model"
	"aegisr/internal/ops"
	"aegisr/internal/state"
)

type ReportView struct {
	GeneratedAt  time.Time
	Summary      string
	Reasoning    model.ReasoningReport
	NextMoves    []string
	DriftSignals []string
	Findings     []string
	State        state.AttackState
}

type outputDTO struct {
	GeneratedAt  time.Time             `json:"generated_at"`
	Summary      string                `json:"summary"`
	Reasoning    model.ReasoningReport `json:"reasoning"`
	State        state.AttackState     `json:"state"`
	NextMoves    []string              `json:"next_moves"`
	DriftSignals []string              `json:"drift_signals"`
	Findings     []string              `json:"findings"`
}

func loadReport(path string) (ReportView, error) {
	var out ReportView
	if path == "" {
		return out, nil
	}
	if !ops.IsSafePath(path) {
		return out, os.ErrInvalid
	}
	//nolint:gosec // path validated via IsSafePath
	data, err := os.ReadFile(path)
	if err != nil {
		return out, err
	}
	var dto outputDTO
	if err := json.Unmarshal(data, &dto); err == nil && (dto.Summary != "" || len(dto.Reasoning.Results) > 0) {
		return ReportView{
			GeneratedAt:  dto.GeneratedAt,
			Summary:      dto.Summary,
			Reasoning:    dto.Reasoning,
			NextMoves:    dto.NextMoves,
			DriftSignals: dto.DriftSignals,
			Findings:     dto.Findings,
			State:        dto.State,
		}, nil
	}
	// Fallback: try to read as reasoning-only report
	var r model.ReasoningReport
	if err := json.Unmarshal(data, &r); err != nil {
		return out, err
	}
	return ReportView{
		GeneratedAt: r.GeneratedAt,
		Summary:     r.Summary,
		Reasoning:   r,
	}, nil
}

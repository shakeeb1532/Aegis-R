package ui

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"

	"aegisr/internal/governance"
	"aegisr/internal/ops"
)

func loadProfiles(path string) ([]governance.AnalystProfile, error) {
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
	var out []governance.AnalystProfile
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func loadDisagreements(path string) ([]governance.Disagreement, error) {
	if path == "" {
		return nil, nil
	}
	if !ops.IsSafePath(path) {
		return nil, os.ErrInvalid
	}
	//nolint:gosec // path validated via IsSafePath
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	out := []governance.Disagreement{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var d governance.Disagreement
		if err := json.Unmarshal([]byte(line), &d); err != nil {
			continue
		}
		out = append(out, d)
	}
	return out, scanner.Err()
}

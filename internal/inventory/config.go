package inventory

import (
	"encoding/json"
	"os"

	"aman/internal/ops"
)

func LoadConfig(path string) (AdapterConfig, error) {
	var cfg AdapterConfig
	if path == "" {
		return cfg, os.ErrInvalid
	}
	if !ops.IsSafePath(path) {
		return cfg, os.ErrInvalid
	}
	//nolint:gosec // path validated
	// #nosec G304
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

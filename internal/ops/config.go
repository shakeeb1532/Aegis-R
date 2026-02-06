package ops

import (
	"encoding/json"
	"os"
)

type Config struct {
	LogLevel   string `json:"log_level"`
	MetricsOn  bool   `json:"metrics_on"`
	StrictMode bool   `json:"strict_mode"`
}

func LoadConfig(path string) (Config, error) {
	var c Config
	if path == "" {
		return c, nil
	}
	if !IsSafePath(path) {
		return c, os.ErrInvalid
	}
	//nolint:gosec // path validated via IsSafePath
	data, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(data, &c); err != nil {
		return c, err
	}
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
	return c, nil
}

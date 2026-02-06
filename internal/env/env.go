package env

import (
	"encoding/json"
	"os"

	"aegisr/internal/ops"
)

type Host struct {
	ID       string   `json:"id"`
	Zone     string   `json:"zone"`
	Tags     []string `json:"tags"`
	Critical bool     `json:"critical"`
}

type Identity struct {
	ID        string   `json:"id"`
	Role      string   `json:"role"`
	PrivLevel string   `json:"priv_level"`
	Tags      []string `json:"tags"`
}

type TrustBoundary struct {
	ID    string `json:"id"`
	From  string `json:"from"`
	To    string `json:"to"`
	Mode  string `json:"mode"` // allow, deny, conditional
	Notes string `json:"notes"`
}

type Environment struct {
	Hosts           []Host          `json:"hosts"`
	Identities      []Identity      `json:"identities"`
	TrustBoundaries []TrustBoundary `json:"trust_boundaries"`
}

func Load(path string) (Environment, error) {
	var e Environment
	if path == "" {
		return e, os.ErrInvalid
	}
	if !ops.IsSafePath(path) {
		return e, os.ErrInvalid
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return e, err
	}
	if err := json.Unmarshal(data, &e); err != nil {
		return e, err
	}
	return e, nil
}

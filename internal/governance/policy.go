package governance

import (
	"encoding/json"
	"os"

	"aman/internal/ops"
)

type Policy struct {
	ID                    string   `json:"id"`
	RequireDualForSignals []string `json:"require_dual_for_signals"`
	MinApprovals          int      `json:"min_approvals"`
	AllowedSignerRoles    []string `json:"allowed_signer_roles"`
}

type Decision struct {
	RequireDual  bool     `json:"require_dual"`
	Reasons      []string `json:"reasons"`
	MinApprovals int      `json:"min_approvals"`
}

func Load(path string) (Policy, error) {
	var p Policy
	if path == "" {
		return p, os.ErrInvalid
	}
	if !ops.IsSafePath(path) {
		return p, os.ErrInvalid
	}
	//nolint:gosec // path validated via IsSafePath
	// #nosec G304
	data, err := os.ReadFile(path)
	if err != nil {
		return p, err
	}
	if err := json.Unmarshal(data, &p); err != nil {
		return p, err
	}
	if p.MinApprovals <= 0 {
		p.MinApprovals = 2
	}
	return p, nil
}

func Evaluate(p Policy, signals []string) Decision {
	need := map[string]bool{}
	for _, s := range p.RequireDualForSignals {
		need[s] = true
	}
	reasons := []string{}
	requireDual := false
	for _, s := range signals {
		if need[s] {
			requireDual = true
			reasons = append(reasons, s)
		}
	}
	return Decision{RequireDual: requireDual, Reasons: reasons, MinApprovals: p.MinApprovals}
}

func RoleAllowed(p Policy, role string) bool {
	if len(p.AllowedSignerRoles) == 0 {
		return true
	}
	for _, r := range p.AllowedSignerRoles {
		if r == role {
			return true
		}
	}
	return false
}

package validate

import (
	"errors"
	"fmt"

	"aman/internal/env"
	"aman/internal/governance"
	"aman/internal/logic"
)

type ValidationError struct {
	Field   string
	Message string
}

type ValidationErrors []ValidationError

func (v ValidationErrors) Error() string {
	out := "validation failed:\n"
	for _, e := range v {
		out += fmt.Sprintf("- %s: %s\n", e.Field, e.Message)
	}
	return out
}

func Rules(rules []logic.Rule) error {
	if err := logic.ValidateRules(rules); err != nil {
		return ValidationErrors{{Field: "rules", Message: "invalid rule set"}}
	}
	return nil
}

func Environment(e env.Environment) error {
	issues := ValidationErrors{}
	if len(e.Hosts) == 0 {
		issues = append(issues, ValidationError{Field: "hosts", Message: "at least one host required"})
	}
	seen := map[string]bool{}
	for _, h := range e.Hosts {
		if h.ID == "" {
			issues = append(issues, ValidationError{Field: "hosts.id", Message: "host id required"})
		}
		if seen[h.ID] {
			issues = append(issues, ValidationError{Field: "hosts.id", Message: "duplicate host id"})
		}
		seen[h.ID] = true
	}
	if len(issues) > 0 {
		return issues
	}
	return nil
}

func Policy(p governance.Policy) error {
	issues := ValidationErrors{}
	if p.ID == "" {
		issues = append(issues, ValidationError{Field: "policy.id", Message: "policy id required"})
	}
	if p.MinApprovals < 1 {
		issues = append(issues, ValidationError{Field: "policy.min_approvals", Message: "must be >= 1"})
	}
	for _, r := range p.AllowedSignerRoles {
		if !governance.IsValidRole(r) {
			issues = append(issues, ValidationError{Field: "policy.allowed_signer_roles", Message: "invalid role: " + r})
		}
	}
	if len(issues) > 0 {
		return issues
	}
	return nil
}

func Must(err error) error {
	if err == nil {
		return nil
	}
	var ve ValidationErrors
	if errors.As(err, &ve) {
		return err
	}
	return ValidationErrors{{Field: "unknown", Message: err.Error()}}
}

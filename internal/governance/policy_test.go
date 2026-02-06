package governance

import "testing"

func TestRoleAllowed(t *testing.T) {
	p := Policy{AllowedSignerRoles: []string{"approver"}}
	if !RoleAllowed(p, "approver") {
		t.Fatalf("expected role allowed")
	}
	if RoleAllowed(p, "analyst") {
		t.Fatalf("expected role denied")
	}
}

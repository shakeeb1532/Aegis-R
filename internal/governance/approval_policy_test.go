package governance

import (
	"testing"
	"time"

	"aman/internal/approval"
)

func TestPolicyRoleEnforcement(t *testing.T) {
	pub, priv, err := approval.GenerateKeypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	app, err := approval.Sign("change-1", 5*time.Minute, true, "alice", "analyst", pub, priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	p := Policy{AllowedSignerRoles: []string{"approver"}}
	if err := approval.VerifySignerRole(app, p.AllowedSignerRoles); err == nil {
		t.Fatalf("expected role rejection")
	}
}

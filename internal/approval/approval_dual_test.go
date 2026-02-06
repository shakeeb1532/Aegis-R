package approval

import (
	"testing"
	"time"
)

func TestVerifyDual(t *testing.T) {
	pub1, priv1, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	pub2, priv2, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	a1, err := Sign("change-1", 5*time.Minute, true, "alice", "approver", pub1, priv1)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	a2, err := Sign("change-1", 5*time.Minute, true, "bob", "approver", pub2, priv2)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	d := DualApproval{Approvals: []Approval{a1, a2}, MinSigners: 2, RequireOkta: true}
	if err := VerifyDual(d, time.Now().UTC()); err != nil {
		t.Fatalf("verify dual: %v", err)
	}
}

func TestVerifyDualRequiresDistinctSigners(t *testing.T) {
	pub1, priv1, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	a1, err := Sign("change-1", 5*time.Minute, true, "alice", "approver", pub1, priv1)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	a2 := a1
	d := DualApproval{Approvals: []Approval{a1, a2}, MinSigners: 2, RequireOkta: true}
	if err := VerifyDual(d, time.Now().UTC()); err == nil {
		t.Fatalf("expected insufficient valid approvals")
	}
}

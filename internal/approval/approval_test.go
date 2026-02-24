package approval

import (
	"testing"
	"time"
)

func TestApprovalVerify(t *testing.T) {
	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	app, err := Sign("change-1", 5*time.Minute, true, "alice", "approver", pub, priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := Verify(app, true, time.Now().UTC()); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestApprovalSignAtDeterministic(t *testing.T) {
	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	now := time.Date(2026, 2, 23, 10, 0, 0, 0, time.UTC)
	app, err := SignAt("change-1", 5*time.Minute, true, "alice", "approver", pub, priv, now)
	if err != nil {
		t.Fatalf("signat: %v", err)
	}
	if !app.IssuedAt.Equal(now) {
		t.Fatalf("expected deterministic issued_at")
	}
}

func TestApprovalExpired(t *testing.T) {
	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	app, err := Sign("change-1", 1*time.Second, true, "alice", "approver", pub, priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := Verify(app, true, app.ExpiresAt.Add(1*time.Second)); err == nil {
		t.Fatalf("expected expiration error")
	}
}

func TestApprovalOktaRequired(t *testing.T) {
	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	app, err := Sign("change-1", 5*time.Minute, false, "alice", "approver", pub, priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := Verify(app, true, time.Now().UTC()); err == nil {
		t.Fatalf("expected okta required error")
	}
}

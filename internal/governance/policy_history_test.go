package governance

import (
	"testing"
	"time"
)

func TestResolveActivePolicy(t *testing.T) {
	now := time.Date(2026, 2, 8, 12, 0, 0, 0, time.UTC)
	policies := []Policy{
		{ID: "p1", Version: "v1", UpdatedAt: "2026-01-01T00:00:00Z", ActiveFrom: "2026-01-01T00:00:00Z"},
		{ID: "p2", Version: "v2", UpdatedAt: "2026-02-01T00:00:00Z", ActiveFrom: "2026-02-01T00:00:00Z", Supersedes: []string{"p1"}},
	}
	active, err := ResolveActive(policies, now)
	if err != nil {
		t.Fatalf("resolve active: %v", err)
	}
	if active.ID != "p2" {
		t.Fatalf("expected p2 active, got %s", active.ID)
	}
}

func TestResolveActivePolicyConflict(t *testing.T) {
	now := time.Date(2026, 2, 8, 12, 0, 0, 0, time.UTC)
	policies := []Policy{
		{ID: "p1", Version: "v1", UpdatedAt: "2026-01-01T00:00:00Z", ActiveFrom: "2026-01-01T00:00:00Z"},
		{ID: "p2", Version: "v2", UpdatedAt: "2026-02-01T00:00:00Z", ActiveFrom: "2026-02-01T00:00:00Z"},
	}
	_, err := ResolveActive(policies, now)
	if err == nil {
		t.Fatalf("expected conflict error")
	}
}

package inventory

import (
	"testing"

	"aman/internal/env"
)

func TestDiffEnv(t *testing.T) {
	before := env.Environment{
		Hosts:           []env.Host{{ID: "h1"}},
		Identities:      []env.Identity{{ID: "u1"}},
		TrustBoundaries: []env.TrustBoundary{{ID: "t1"}},
	}
	after := env.Environment{
		Hosts:           []env.Host{{ID: "h2"}},
		Identities:      []env.Identity{{ID: "u1"}, {ID: "u2"}},
		TrustBoundaries: []env.TrustBoundary{{ID: "t1"}, {ID: "t2"}},
	}
	rep := DiffEnv(before, after)
	if len(rep.AddedHosts) != 1 || rep.AddedHosts[0].ID != "h2" {
		t.Fatalf("expected added host h2")
	}
	if len(rep.RemovedHosts) != 1 || rep.RemovedHosts[0].ID != "h1" {
		t.Fatalf("expected removed host h1")
	}
	if len(rep.AddedIdentities) != 1 || rep.AddedIdentities[0].ID != "u2" {
		t.Fatalf("expected added identity u2")
	}
	if len(rep.RemovedIdentites) != 0 {
		t.Fatalf("expected no removed identities")
	}
	if len(rep.AddedTrusts) != 1 || rep.AddedTrusts[0].ID != "t2" {
		t.Fatalf("expected added trust t2")
	}
}

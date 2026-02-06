package env

import "testing"

func TestAttackPathRegression(t *testing.T) {
	env := Environment{
		Hosts: []Host{{ID: "h1", Zone: "a"}, {ID: "h2", Zone: "b"}, {ID: "h3", Zone: "c"}},
		TrustBoundaries: []TrustBoundary{
			{ID: "tb1", From: "a", To: "b", Mode: "allow"},
			{ID: "tb2", From: "b", To: "c", Mode: "allow"},
		},
	}
	g := BuildGraph(env)
	reach := g.ReachableFrom([]string{"zone:a"})
	if !reach["zone:c"] {
		t.Fatalf("expected zone c reachable")
	}
}

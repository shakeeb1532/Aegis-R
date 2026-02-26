package env

import "testing"

func TestReachableGraph(t *testing.T) {
	env := Environment{
		TrustBoundaries: []TrustBoundary{
			{ID: "tb1", From: "a", To: "b", Mode: "allow"},
			{ID: "tb2", From: "b", To: "c", Mode: "allow"},
		},
	}
	g := BuildGraph(env, nil)
	reach := g.ReachableFrom([]string{"zone:a"})
	if !reach["zone:c"] {
		t.Fatalf("expected zone c reachable")
	}
}

func TestReachableGraph_RespectsDenyBoundary(t *testing.T) {
	env := Environment{
		TrustBoundaries: []TrustBoundary{
			{ID: "tb1", From: "a", To: "b", Mode: "allow"},
			{ID: "tb2", From: "b", To: "c", Mode: "allow"},
			{ID: "tb3", From: "a", To: "c", Mode: "deny"},
		},
	}
	g := BuildGraph(env, nil)
	reach := g.ReachableFrom([]string{"zone:a"})
	if reach["zone:c"] {
		t.Fatalf("expected zone c not reachable due to deny boundary")
	}
}

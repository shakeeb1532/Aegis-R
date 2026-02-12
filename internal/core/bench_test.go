package core

import (
	"testing"
	"time"

	"aman/internal/env"
	"aman/internal/logic"
	"aman/internal/model"
	"aman/internal/state"
)

func BenchmarkAssess1k(b *testing.B)   { benchmarkAssess(b, 1000) }
func BenchmarkAssess10k(b *testing.B)  { benchmarkAssess(b, 10000) }
func BenchmarkAssess100k(b *testing.B) { benchmarkAssess(b, 100000) }

func benchmarkAssess(b *testing.B, n int) {
	events := makeEvents(n)
	rules := logic.DefaultRules()
	environment := env.Environment{
		Hosts: []env.Host{
			{ID: "host-1", Zone: "user-net", Critical: false},
			{ID: "host-2", Zone: "server-net", Critical: true},
			{ID: "host-3", Zone: "server-net", Critical: true},
		},
		Identities: []env.Identity{
			{ID: "alice", PrivLevel: "medium"},
			{ID: "svc-admin", PrivLevel: "high"},
		},
		TrustBoundaries: []env.TrustBoundary{{ID: "tb-1", From: "user-net", To: "server-net", Mode: "allow"}},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Assess(events, rules, environment, state.New())
	}
}

func makeEvents(n int) []model.Event {
	events := make([]model.Event, 0, n)
	base := time.Now().UTC()
	for i := 0; i < n; i++ {
		events = append(events, model.Event{
			ID:   "e",
			Time: base.Add(time.Duration(i) * time.Millisecond),
			Host: "host-1",
			User: "alice",
			Type: eventType(i),
			Details: map[string]interface{}{
				"src_ip": "10.0.0.1",
				"dst_ip": "10.0.0.2",
			},
		})
	}
	return events
}

func eventType(i int) string {
	switch i % 10 {
	case 0:
		return "email_attachment_open"
	case 1:
		return "macro_execution"
	case 2:
		return "beacon_outbound"
	case 3:
		return "token_manipulation"
	case 4:
		return "admin_group_change"
	case 5:
		return "lsass_access"
	case 6:
		return "remote_service_creation"
	case 7:
		return "network_logon"
	case 8:
		return "trust_boundary_change"
	default:
		return "policy_override"
	}
}

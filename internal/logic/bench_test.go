package logic

import (
	"testing"
	"time"

	"aegisr/internal/model"
)

func BenchmarkReason1k(b *testing.B)   { benchmarkReason(b, 1000) }
func BenchmarkReason10k(b *testing.B)  { benchmarkReason(b, 10000) }
func BenchmarkReason100k(b *testing.B) { benchmarkReason(b, 100000) }

func benchmarkReason(b *testing.B, n int) {
	events := makeEvents(n)
	rules := DefaultRules()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Reason(events, rules)
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
	switch i % 8 {
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
	default:
		return "network_logon"
	}
}

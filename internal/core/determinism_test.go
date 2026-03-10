package core

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"testing"
	"time"

	"aman/internal/env"
	"aman/internal/logic"
	"aman/internal/model"
	"aman/internal/state"
)

func TestAssessDeterministicModeStableAcrossRunsAndOrder(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	runtime := RuntimeOptions{Now: now, Deterministic: true}
	environment := env.Environment{
		Hosts: []env.Host{
			{ID: "idp-1", Zone: "identity"},
			{ID: "web-01", Zone: "corp"},
		},
		Identities: []env.Identity{
			{ID: "alice", PrivLevel: "high"},
		},
	}
	events := []model.Event{
		{ID: "1", Time: time.Date(2026, 2, 1, 10, 0, 0, 0, time.UTC), Host: "idp-1", User: "alice", Type: "impossible_travel"},
		{ID: "2", Time: time.Date(2026, 2, 1, 10, 0, 5, 0, time.UTC), Host: "idp-1", User: "alice", Type: "new_device_login"},
		{ID: "3", Time: time.Date(2026, 2, 1, 10, 1, 0, 0, time.UTC), Host: "web-01", User: "alice", Type: "email_attachment_open"},
		{ID: "4", Time: time.Date(2026, 2, 1, 10, 1, 5, 0, time.UTC), Host: "web-01", User: "alice", Type: "macro_execution"},
		{ID: "5", Time: time.Date(2026, 2, 1, 10, 1, 10, 0, time.UTC), Host: "web-01", User: "alice", Type: "beacon_outbound"},
		{ID: "6", Time: time.Date(2026, 2, 1, 10, 1, 15, 0, time.UTC), Host: "web-01", User: "alice", Type: "process_creation"},
		{ID: "7", Time: time.Date(2026, 2, 1, 10, 1, 20, 0, time.UTC), Host: "web-01", User: "alice", Type: "lolbin_execution"},
	}
	rules := []logic.Rule{
		mustRule(t, "TA0001.PHISHING"),
		mustRule(t, "TA0002.LOLBIN_CHAIN"),
		mustRule(t, "TA0006.IDENTITY_ANOMALY"),
	}

	out1 := AssessWithOptions(events, rules, environment, state.NewAt(now), nil, false, runtime)
	out2 := AssessWithOptions(events, rules, environment, state.NewAt(now), nil, false, runtime)
	if digestOutput(t, out1) != digestOutput(t, out2) {
		t.Fatalf("deterministic mode changed across identical runs")
	}

	shuffled := append([]model.Event(nil), events...)
	sort.SliceStable(shuffled, func(i, j int) bool {
		return shuffled[i].ID > shuffled[j].ID
	})
	out3 := AssessWithOptions(shuffled, rules, environment, state.NewAt(now), nil, false, runtime)
	if digestOutput(t, out1) != digestOutput(t, out3) {
		t.Fatalf("deterministic mode changed across input ordering")
	}
}

func mustRule(t *testing.T, id string) logic.Rule {
	t.Helper()
	for _, r := range logic.DefaultRules() {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("rule not found: %s", id)
	return logic.Rule{}
}

func digestOutput(t *testing.T, out Output) string {
	t.Helper()
	data, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshal output: %v", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

package logic

import (
	"testing"
	"time"

	"aman/internal/model"
)

func TestReasonFeasibleChain(t *testing.T) {
	events := []model.Event{
		{ID: "1", Time: time.Now(), Host: "host-1", User: "alice", Type: "email_attachment_open"},
		{ID: "2", Time: time.Now(), Host: "host-1", User: "alice", Type: "macro_execution"},
		{ID: "3", Time: time.Now(), Host: "host-1", User: "alice", Type: "beacon_outbound"},
		{ID: "4", Time: time.Now(), Host: "host-1", User: "alice", Type: "token_manipulation"},
		{ID: "5", Time: time.Now(), Host: "host-1", User: "alice", Type: "admin_group_change"},
		{ID: "6", Time: time.Now(), Host: "host-1", User: "alice", Type: "lsass_access"},
		{ID: "7", Time: time.Now(), Host: "host-1", User: "alice", Type: "remote_service_creation"},
		{ID: "8", Time: time.Now(), Host: "host-1", User: "alice", Type: "network_logon"},
		{ID: "9", Time: time.Now(), Host: "host-1", User: "alice", Type: "data_staging"},
		{ID: "10", Time: time.Now(), Host: "host-1", User: "alice", Type: "large_outbound_transfer"},
	}

	rep := Reason(events, DefaultRules())
	found := false
	for _, r := range rep.Results {
		if r.RuleID == "TA0010.EXFIL" {
			found = true
			if !r.Feasible {
				t.Fatalf("expected exfil to be feasible")
			}
		}
	}
	if !found {
		t.Fatalf("exfil rule not found")
	}
}

func TestReasonMissingEvidence(t *testing.T) {
	events := []model.Event{
		{ID: "1", Time: time.Now(), Type: "email_attachment_open"},
		{ID: "2", Time: time.Now(), Type: "macro_execution"},
	}

	rep := Reason(events, DefaultRules())
	for _, r := range rep.Results {
		if r.RuleID == "TA0001.PHISHING" {
			if r.Feasible {
				t.Fatalf("expected phishing to be not feasible due to missing beacon")
			}
			if len(r.MissingEvidence) == 0 {
				t.Fatalf("expected missing evidence")
			}
		}
	}
}

func TestReasonCausalOrdering_PreconditionAfterEffect(t *testing.T) {
	// Persistence evidence appears before initial_access chain.
	events := []model.Event{
		{ID: "1", Time: time.Date(2026, 2, 1, 10, 0, 0, 0, time.UTC), Host: "host-1", User: "alice", Type: "registry_run_key"},
		{ID: "2", Time: time.Date(2026, 2, 1, 10, 1, 0, 0, time.UTC), Host: "host-1", User: "alice", Type: "scheduled_task"},
		{ID: "3", Time: time.Date(2026, 2, 1, 10, 5, 0, 0, time.UTC), Host: "host-1", User: "alice", Type: "email_attachment_open"},
		{ID: "4", Time: time.Date(2026, 2, 1, 10, 6, 0, 0, time.UTC), Host: "host-1", User: "alice", Type: "macro_execution"},
	}

	rep := Reason(events, DefaultRules())
	for _, r := range rep.Results {
		if r.RuleID == "TA0003.PERSIST" {
			if r.Feasible {
				t.Fatalf("expected infeasible when precondition ordering is violated")
			}
			if r.PrecondOK {
				t.Fatalf("expected precond_ok=false for precondition ordering failure")
			}
			found := false
			for _, m := range r.MissingEvidence {
				if m.Type == "precond_order:initial_access" {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("expected precond_order gap for initial_access")
			}
			return
		}
	}
	t.Fatalf("persist rule not found")
}

func TestReasonIncludesCausalBlockers(t *testing.T) {
	events := []model.Event{
		{ID: "1", Time: time.Date(2026, 2, 1, 10, 0, 0, 0, time.UTC), Host: "host-1", User: "alice", Type: "email_attachment_open"},
		{ID: "2", Time: time.Date(2026, 2, 1, 10, 1, 0, 0, time.UTC), Host: "host-1", User: "alice", Type: "macro_execution"},
	}
	rep := Reason(events, DefaultRules())
	for _, r := range rep.Results {
		if r.RuleID == "TA0001.PHISHING" {
			if len(r.CausalBlockers) == 0 {
				t.Fatalf("expected causal blockers for infeasible rule")
			}
			return
		}
	}
	t.Fatalf("rule not found")
}

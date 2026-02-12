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

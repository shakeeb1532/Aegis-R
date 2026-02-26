package logic

import (
	"math/rand"
	"testing"
	"time"

	"aman/internal/env"
	"aman/internal/model"
)

func TestReasonWithEnv_FallbackWhenEnvEmpty(t *testing.T) {
	events := []model.Event{
		{ID: "e1", Time: time.Date(2026, 2, 1, 10, 0, 0, 0, time.UTC), Host: "h1", User: "alice", Type: "email_attachment_open"},
		{ID: "e2", Time: time.Date(2026, 2, 1, 10, 1, 0, 0, time.UTC), Host: "h1", User: "alice", Type: "macro_execution"},
		{ID: "e3", Time: time.Date(2026, 2, 1, 10, 2, 0, 0, time.UTC), Host: "h1", User: "alice", Type: "beacon_outbound"},
	}
	rules := []Rule{rulesWithIDOrFallback("TA0001.PHISHING")[0]}
	empty := env.Environment{}

	old := ReasonWithMetrics(events, rules, nil, false)
	newRep := ReasonWithEnv(events, rules, empty)
	if old.ConfidenceModel != newRep.ConfidenceModel {
		t.Fatalf("fallback mismatch: old=%s new=%s", old.ConfidenceModel, newRep.ConfidenceModel)
	}
	if old.Results[0].Feasible != newRep.Results[0].Feasible {
		t.Fatalf("fallback feasible mismatch")
	}
}

func TestReasonWithEnv_LateralBlockedWhenUnreachable(t *testing.T) {
	environment := env.Environment{
		Hosts: []env.Host{
			{ID: "h1", Zone: "user-net"},
			{ID: "h2", Zone: "secure-net"},
		},
	}
	events := []model.Event{
		{ID: "e0", Time: time.Date(2026, 2, 1, 10, 0, 0, 0, time.UTC), Host: "h1", User: "alice", Type: "lsass_access"},
		{ID: "e1", Time: time.Date(2026, 2, 1, 10, 1, 0, 0, time.UTC), Host: "h2", User: "alice", Type: "remote_service_creation"},
		{ID: "e2", Time: time.Date(2026, 2, 1, 10, 2, 0, 0, time.UTC), Host: "h2", User: "alice", Type: "network_logon"},
	}
	rep := ReasonWithEnv(events, rulesWithIDOrFallback("TA0008.LATERAL"), environment)
	r := findResultOrFail(t, rep, "TA0008.LATERAL")
	if r.Feasible {
		t.Fatalf("expected infeasible when target zone unreachable")
	}
	if r.ReasonCode != "env_unreachable" {
		t.Fatalf("expected reason code env_unreachable, got %q", r.ReasonCode)
	}
}

func TestReasonWithEnv_LateralAllowedWhenReachable(t *testing.T) {
	environment := env.Environment{
		Hosts: []env.Host{
			{ID: "h1", Zone: "user-net"},
			{ID: "h2", Zone: "secure-net"},
		},
		TrustBoundaries: []env.TrustBoundary{
			{ID: "tb1", From: "user-net", To: "secure-net", Mode: "allow"},
		},
	}
	events := []model.Event{
		{ID: "e0", Time: time.Date(2026, 2, 1, 10, 0, 0, 0, time.UTC), Host: "h1", User: "alice", Type: "lsass_access"},
		{ID: "e1", Time: time.Date(2026, 2, 1, 10, 1, 0, 0, time.UTC), Host: "h2", User: "alice", Type: "remote_service_creation"},
		{ID: "e2", Time: time.Date(2026, 2, 1, 10, 2, 0, 0, time.UTC), Host: "h2", User: "alice", Type: "network_logon"},
	}
	rep := ReasonWithEnv(events, rulesWithIDOrFallback("TA0008.LATERAL"), environment)
	r := findResultOrFail(t, rep, "TA0008.LATERAL")
	if !r.Feasible {
		t.Fatalf("expected feasible when zones are reachable")
	}
}

func TestReasonWithEnv_PrivilegeGate(t *testing.T) {
	events := []model.Event{
		{ID: "p1", Time: time.Date(2026, 2, 1, 10, 0, 0, 0, time.UTC), Host: "h1", User: "alice", Type: "token_manipulation"},
		{ID: "e1", Time: time.Date(2026, 2, 1, 10, 1, 0, 0, time.UTC), Host: "h1", User: "alice", Type: "credential_dumping"},
		{ID: "e2", Time: time.Date(2026, 2, 1, 10, 2, 0, 0, time.UTC), Host: "h1", User: "alice", Type: "lsass_access"},
	}
	rules := rulesWithIDOrFallback("TA0006.CREDDUMP")

	low := env.Environment{
		Hosts: []env.Host{{ID: "h1", Zone: "user-net"}},
		Identities: []env.Identity{
			{ID: "alice", PrivLevel: "standard"},
		},
	}
	repLow := ReasonWithEnv(events, rules, low)
	rLow := findResultOrFail(t, repLow, "TA0006.CREDDUMP")
	if rLow.Feasible {
		t.Fatalf("expected infeasible for standard privilege")
	}
	if rLow.ReasonCode != "identity_insufficient_priv" {
		t.Fatalf("expected identity_insufficient_priv, got %q", rLow.ReasonCode)
	}

	high := env.Environment{
		Hosts: []env.Host{{ID: "h1", Zone: "user-net"}},
		Identities: []env.Identity{
			{ID: "alice", PrivLevel: "high"},
		},
	}
	repHigh := ReasonWithEnv(events, rules, high)
	rHigh := findResultOrFail(t, repHigh, "TA0006.CREDDUMP")
	if !rHigh.Feasible {
		t.Fatalf("expected feasible for high privilege")
	}

	unknown := env.Environment{
		Hosts:      []env.Host{{ID: "h1", Zone: "user-net"}},
		Identities: []env.Identity{},
	}
	repUnknown := ReasonWithEnv(events, rules, unknown)
	rUnknown := findResultOrFail(t, repUnknown, "TA0006.CREDDUMP")
	if rUnknown.Feasible {
		t.Fatalf("expected infeasible for unknown privilege context")
	}
	if rUnknown.ReasonCode != "environment_unknown" {
		t.Fatalf("expected environment_unknown, got %q", rUnknown.ReasonCode)
	}
}

func TestReasonWithEnv_DeterministicWithFixedClock(t *testing.T) {
	events := []model.Event{
		{ID: "e1", Time: time.Date(2026, 2, 1, 10, 0, 0, 0, time.UTC), Host: "h1", User: "alice", Type: "email_attachment_open"},
		{ID: "e2", Time: time.Date(2026, 2, 1, 10, 1, 0, 0, time.UTC), Host: "h1", User: "alice", Type: "macro_execution"},
		{ID: "e3", Time: time.Date(2026, 2, 1, 10, 2, 0, 0, time.UTC), Host: "h1", User: "alice", Type: "beacon_outbound"},
	}
	rules := rulesWithIDOrFallback("TA0001.PHISHING")
	environment := env.Environment{Hosts: []env.Host{{ID: "h1", Zone: "user-net"}}}

	cfg := ReasonerConfig{
		Now: func() time.Time { return time.Date(2026, 2, 1, 11, 0, 0, 0, time.UTC) },
	}
	a := ReasonWithEnvWithConfig(events, rules, environment, cfg)
	b := ReasonWithEnvWithConfig(events, rules, environment, cfg)
	if a.Results[0].Confidence != b.Results[0].Confidence {
		t.Fatalf("non-deterministic confidence: %.6f != %.6f", a.Results[0].Confidence, b.Results[0].Confidence)
	}
}

func TestReasonWithEnv_CausalOrdering_PreconditionAfterEffect(t *testing.T) {
	environment := env.Environment{Hosts: []env.Host{{ID: "h1", Zone: "user-net"}}}
	events := []model.Event{
		{ID: "1", Time: time.Date(2026, 2, 1, 10, 0, 0, 0, time.UTC), Host: "h1", User: "alice", Type: "registry_run_key"},
		{ID: "2", Time: time.Date(2026, 2, 1, 10, 1, 0, 0, time.UTC), Host: "h1", User: "alice", Type: "scheduled_task"},
		{ID: "3", Time: time.Date(2026, 2, 1, 10, 5, 0, 0, time.UTC), Host: "h1", User: "alice", Type: "email_attachment_open"},
		{ID: "4", Time: time.Date(2026, 2, 1, 10, 6, 0, 0, time.UTC), Host: "h1", User: "alice", Type: "macro_execution"},
	}
	rep := ReasonWithEnv(events, rulesWithIDOrFallback("TA0003.PERSIST"), environment)
	r := findResultOrFail(t, rep, "TA0003.PERSIST")
	if r.Feasible {
		t.Fatalf("expected infeasible when precondition arrives after dependent evidence")
	}
	found := false
	for _, m := range r.MissingEvidence {
		if m.Type == "precond_order:initial_access" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected precond_order reason in missing evidence")
	}
}

func TestReasonWithEnv_FeasibleHasNecessaryCauses(t *testing.T) {
	environment := env.Environment{Hosts: []env.Host{{ID: "h1", Zone: "user-net"}}}
	events := []model.Event{
		{ID: "e1", Time: time.Date(2026, 2, 1, 10, 0, 0, 0, time.UTC), Host: "h1", User: "alice", Type: "email_attachment_open"},
		{ID: "e2", Time: time.Date(2026, 2, 1, 10, 1, 0, 0, time.UTC), Host: "h1", User: "alice", Type: "macro_execution"},
		{ID: "e3", Time: time.Date(2026, 2, 1, 10, 2, 0, 0, time.UTC), Host: "h1", User: "alice", Type: "beacon_outbound"},
	}
	rep := ReasonWithEnv(events, rulesWithIDOrFallback("TA0001.PHISHING"), environment)
	r := findResultOrFail(t, rep, "TA0001.PHISHING")
	if !r.Feasible {
		t.Fatalf("expected feasible")
	}
	if len(r.NecessaryCauses) == 0 {
		t.Fatalf("expected necessary causes on feasible outcome")
	}
	if len(r.NecessaryCauseSets) == 0 {
		t.Fatalf("expected necessary cause sets on feasible outcome")
	}
}

func TestReasonWithEnv_PropertyFeasibleHasNoCausalBlockers(t *testing.T) {
	environment := env.Environment{Hosts: []env.Host{{ID: "h1", Zone: "user-net"}}}
	rules := rulesWithIDOrFallback("TA0001.PHISHING")
	base := []model.Event{
		{ID: "e1", Time: time.Date(2026, 2, 1, 10, 0, 0, 0, time.UTC), Host: "h1", User: "alice", Type: "email_attachment_open"},
		{ID: "e2", Time: time.Date(2026, 2, 1, 10, 1, 0, 0, time.UTC), Host: "h1", User: "alice", Type: "macro_execution"},
		{ID: "e3", Time: time.Date(2026, 2, 1, 10, 2, 0, 0, time.UTC), Host: "h1", User: "alice", Type: "beacon_outbound"},
	}
	rng := rand.New(rand.NewSource(42))
	for i := 0; i < 100; i++ {
		events := append([]model.Event{}, base...)
		if rng.Intn(2) == 0 {
			events = events[:2] // remove one required event
		}
		rep := ReasonWithEnv(events, rules, environment)
		r := findResultOrFail(t, rep, "TA0001.PHISHING")
		if r.Feasible && len(r.CausalBlockers) != 0 {
			t.Fatalf("invariant violated: feasible result has blockers: %#v", r.CausalBlockers)
		}
	}
}

func TestReasonWithEnv_CustomReachabilityFailsClosedWithoutTargetContext(t *testing.T) {
	tr := true
	rules := []Rule{
		{
			ID:   "CUSTOM.REACH",
			Name: "Custom Reachability Rule",
			Requirements: []model.EvidenceRequirement{
				{Type: "custom_signal", Description: "custom signal"},
			},
			RequiresReachability: &tr,
			// No target_event_types on purpose.
		},
	}
	environment := env.Environment{
		Hosts: []env.Host{{ID: "h1", Zone: "user-net"}},
	}
	events := []model.Event{
		{ID: "x1", Time: time.Date(2026, 2, 1, 10, 0, 0, 0, time.UTC), Type: "custom_signal"},
	}
	rep := ReasonWithEnv(events, rules, environment)
	r := findResultOrFail(t, rep, "CUSTOM.REACH")
	if r.Feasible {
		t.Fatalf("expected infeasible when required reachability target context is missing")
	}
	if r.ReasonCode != "environment_unknown" {
		t.Fatalf("expected environment_unknown, got %q", r.ReasonCode)
	}
}

func rulesWithIDOrFallback(id string) []Rule {
	for _, r := range DefaultRules() {
		if r.ID == id {
			return []Rule{r}
		}
	}
	return DefaultRules()
}

func findResultOrFail(t *testing.T, rep model.ReasoningReport, ruleID string) model.RuleResult {
	t.Helper()
	for _, r := range rep.Results {
		if r.RuleID == ruleID {
			return r
		}
	}
	t.Fatalf("result for %s not found", ruleID)
	return model.RuleResult{}
}

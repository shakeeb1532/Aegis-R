package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"aman/internal/core"
	"aman/internal/env"
	"aman/internal/model"
	"aman/internal/state"
)

func TestEnforceAmanEscalationAuthority(t *testing.T) {
	rep := model.ReasoningReport{
		AIOverlay: model.AIOverlaySummary{
			Enabled:        true,
			CandidateCount: 2,
			EscalatedCount: 2,
		},
		AIAlerts: []model.AIAlert{
			{RuleID: "R1", Status: "escalated"},
			{RuleID: "R2", Status: "escalated"},
		},
		Results: []model.RuleResult{
			{RuleID: "R1", Feasible: true},
			{RuleID: "R2", Feasible: false},
		},
	}

	enforceAmanEscalationAuthority(&rep)

	if rep.AIAlerts[0].Status != "escalated" {
		t.Fatalf("expected R1 to stay escalated")
	}
	if rep.AIAlerts[1].Status != "triaged" {
		t.Fatalf("expected R2 to be downgraded, got %s", rep.AIAlerts[1].Status)
	}
	if rep.AIOverlay.EscalatedCount != 1 || rep.AIOverlay.TriagedCount != 1 {
		t.Fatalf("unexpected overlay counts: escalated=%d triaged=%d", rep.AIOverlay.EscalatedCount, rep.AIOverlay.TriagedCount)
	}
}

func TestRunIntegrationReadiness(t *testing.T) {
	rulesPath, err := filepath.Abs("../../data/rules.json")
	if err != nil {
		t.Fatalf("abs path failed: %v", err)
	}
	rep, err := runIntegrationReadiness(rulesPath, "", false, 1, 1)
	if err != nil {
		t.Fatalf("integration readiness failed: %v", err)
	}
	if len(rep.Checks) != 3 {
		t.Fatalf("expected 3 checks, got %d", len(rep.Checks))
	}
	if rep.Passed == 0 {
		t.Fatalf("expected at least one passing integration check")
	}
}

func TestRunIntegrationQuickstart(t *testing.T) {
	rulesPath, err := filepath.Abs("../../data/rules.json")
	if err != nil {
		t.Fatalf("abs path failed: %v", err)
	}
	outDir := t.TempDir()
	rep, err := runIntegrationQuickstart(rulesPath, "", outDir, 0.20, 20)
	if err != nil {
		t.Fatalf("quickstart failed: %v", err)
	}
	if len(rep.Runs) != 3 {
		t.Fatalf("expected 3 runs, got %d", len(rep.Runs))
	}
	if rep.Passed == 0 {
		t.Fatalf("expected at least one passing quickstart run")
	}
}

func TestAssessWithConstraints_PreservesEnvAwareReasonCodes(t *testing.T) {
	dir := t.TempDir()

	rulesPath, err := filepath.Abs("../../data/rules.json")
	if err != nil {
		t.Fatalf("abs path failed: %v", err)
	}

	eventsPath := filepath.Join(dir, "events.json")
	envPath := filepath.Join(dir, "env.json")
	statePath := filepath.Join(dir, "state.json")
	auditPath := filepath.Join(dir, "audit.log")
	siemPath := filepath.Join(dir, "siem.json")
	baselinePath := filepath.Join(dir, "baseline.json")
	constraintsPath := filepath.Join(dir, "constraints.json")
	outPath := filepath.Join(dir, "report.json")

	events := []model.Event{
		{ID: "e0", Time: time.Date(2026, 2, 1, 10, 0, 0, 0, time.UTC), Host: "h1", User: "alice", Type: "lsass_access"},
		{ID: "e1", Time: time.Date(2026, 2, 1, 10, 1, 0, 0, time.UTC), Host: "h2", User: "alice", Type: "remote_service_creation"},
		{ID: "e2", Time: time.Date(2026, 2, 1, 10, 2, 0, 0, time.UTC), Host: "h2", User: "alice", Type: "network_logon"},
	}
	environment := env.Environment{
		Hosts: []env.Host{
			{ID: "h1", Zone: "user-net"},
			{ID: "h2", Zone: "secure-net"},
		},
	}
	baseline := map[string]interface{}{
		"created_at": time.Now().UTC().Format(time.RFC3339),
		"root":       dir,
		"hashes": map[string]string{
			"dummy.txt": "deadbeef",
		},
	}

	writeJSONFileForTest(t, eventsPath, events)
	writeJSONFileForTest(t, envPath, environment)
	if err := state.Save(statePath, state.New()); err != nil {
		t.Fatalf("state save failed: %v", err)
	}
	writeJSONFileForTest(t, baselinePath, baseline)
	writeJSONFileForTest(t, constraintsPath, []map[string]interface{}{})

	handleAssess([]string{
		"-in", eventsPath,
		"-env", envPath,
		"-rules", rulesPath,
		"-state", statePath,
		"-audit", auditPath,
		"-siem", siemPath,
		"-baseline", baselinePath,
		"-constraints", constraintsPath,
		"-format", "json",
		"-out", outPath,
	})

	raw, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read report failed: %v", err)
	}
	var out core.Output
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal report failed: %v", err)
	}

	found := false
	for _, r := range out.Reasoning.Results {
		if r.RuleID != "TA0008.LATERAL" {
			continue
		}
		found = true
		if r.ReasonCode != "env_unreachable" {
			t.Fatalf("expected env_unreachable, got %q", r.ReasonCode)
		}
		break
	}
	if !found {
		t.Fatalf("TA0008.LATERAL result not found")
	}
}

func writeJSONFileForTest(t *testing.T, path string, v interface{}) {
	t.Helper()
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("marshal %s failed: %v", path, err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("write %s failed: %v", path, err)
	}
}

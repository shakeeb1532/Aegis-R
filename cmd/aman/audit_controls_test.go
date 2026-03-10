package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"aman/internal/approval"
	"aman/internal/audit"
	"aman/internal/core"
	"aman/internal/logic"
	"aman/internal/model"
)

func TestBuildControlsExportIncludesLifecycleAndDecisionLinkage(t *testing.T) {
	tmp := t.TempDir()

	rulesPath := filepath.Join(tmp, "rules.json")
	rulesBytes, err := json.Marshal(logic.DefaultRules())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rulesPath, rulesBytes, 0600); err != nil {
		t.Fatal(err)
	}

	policyPath := filepath.Join(tmp, "policy.json")
	if err := os.WriteFile(policyPath, []byte(`{"id":"policy-1","min_approvals":2,"allowed_signer_roles":["approver"],"require_dual_for_signals":["TA0006.CREDDUMP"]}`), 0600); err != nil {
		t.Fatal(err)
	}

	artifact := audit.Artifact{
		ID:        "decision-1",
		CreatedAt: time.Date(2026, 3, 7, 10, 0, 0, 0, time.UTC),
		Summary:   "credential dumping decision",
		Findings:  []string{"TA0006.CREDDUMP feasible with confidence 0.91"},
		Reasoning: []string{"credential dumping observed"},
	}
	hash, err := audit.HashArtifact(artifact)
	if err != nil {
		t.Fatal(err)
	}
	artifact.Hash = hash

	auditPath := filepath.Join(tmp, "audit.log")
	artifactBytes, err := json.Marshal(artifact)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(auditPath, append(artifactBytes, '\n'), 0600); err != nil {
		t.Fatal(err)
	}

	pub, priv, err := approval.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	app, err := approval.SignAt("decision-1", 10*time.Minute, true, "alice", "approver", pub, priv, time.Date(2026, 3, 7, 10, 5, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	rec := approvalRecord{
		Approval:   app,
		Rationale:  "validated by governance review",
		TemplateID: "tpl-1",
	}
	approvalsPath := filepath.Join(tmp, "approvals.log")
	recBytes, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(approvalsPath, append(recBytes, '\n'), 0600); err != nil {
		t.Fatal(err)
	}

	reportPath := filepath.Join(tmp, "report.json")
	report := core.Output{
		GeneratedAt: time.Date(2026, 3, 7, 10, 6, 0, 0, time.UTC),
		Reasoning: model.ReasoningReport{
			Results: []model.RuleResult{
				{
					RuleID:        "TA0006.CREDDUMP",
					Name:          "Credential Dumping",
					Feasible:      true,
					PrecondOK:     true,
					DecisionLabel: "escalate",
					ReasonCode:    "verified_signal",
				},
			},
		},
	}
	reportBytes, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(reportPath, reportBytes, 0600); err != nil {
		t.Fatal(err)
	}

	export, err := buildControlsExport(auditPath, "", approvalsPath, reportPath, rulesPath, "", policyPath, false)
	if err != nil {
		t.Fatal(err)
	}

	if !export.AuditChainVerified {
		t.Fatalf("expected verified audit chain, got error: %s", export.AuditChainError)
	}
	if export.AuditLifecycle.IntegrityModel != "append_only_hash_chain" {
		t.Fatalf("unexpected integrity model: %s", export.AuditLifecycle.IntegrityModel)
	}
	if export.PolicyLifecycle.EvaluationMode != "export_time_snapshot" {
		t.Fatalf("unexpected policy evaluation mode: %s", export.PolicyLifecycle.EvaluationMode)
	}
	if export.GovernanceLifecycle.DualControlModel != "human_governed_dual_control" {
		t.Fatalf("unexpected governance lifecycle model: %s", export.GovernanceLifecycle.DualControlModel)
	}
	if len(export.DecisionControls) != 1 {
		t.Fatalf("expected 1 decision control link, got %d", len(export.DecisionControls))
	}
	link := export.DecisionControls[0]
	if link.RuleName != "Credential Dumping" {
		t.Fatalf("unexpected rule name: %s", link.RuleName)
	}
	if link.DecisionLabel != "escalate" {
		t.Fatalf("unexpected decision label: %s", link.DecisionLabel)
	}
	if len(link.ControlIDs) == 0 {
		t.Fatal("expected flattened control ids")
	}
	if len(export.DualApprovals) != 1 {
		t.Fatalf("expected 1 approval summary, got %d", len(export.DualApprovals))
	}
	if len(export.DualApprovals[0].Rationales) != 1 || export.DualApprovals[0].Rationales[0] != "validated by governance review" {
		t.Fatalf("unexpected rationales: %+v", export.DualApprovals[0].Rationales)
	}
	if export.DualApprovals[0].TemplateIDs[0] != "tpl-1" {
		t.Fatalf("unexpected template ids: %+v", export.DualApprovals[0].TemplateIDs)
	}
}

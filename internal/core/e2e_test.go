package core

import (
	"os"
	"testing"
	"time"

	"aegisr/internal/audit"
	"aegisr/internal/env"
	"aegisr/internal/logic"
	"aegisr/internal/model"
	"aegisr/internal/state"
)

func TestEndToEndAssessAudit(t *testing.T) {
	environment := env.Environment{
		Hosts:           []env.Host{{ID: "host-1", Zone: "user-net"}},
		TrustBoundaries: []env.TrustBoundary{{ID: "tb-1", From: "user-net", To: "server-net", Mode: "allow"}},
	}
	events := []model.Event{{ID: "e1", Time: time.Now().UTC(), Host: "host-1", User: "alice", Type: "beacon_outbound"}}

	out := AssessWithMetrics(events, logic.DefaultRules(), environment, state.New(), nil, false)
	if len(out.Findings) == 0 {
		t.Fatalf("expected findings")
	}

	f, err := os.CreateTemp("", "audit-*.log")
	if err != nil {
		t.Fatalf("temp: %v", err)
	}
	defer os.Remove(f.Name())
	f.Close()

	artifact := audit.Artifact{ID: "a1", CreatedAt: time.Now().UTC(), Summary: out.Summary, Findings: out.Findings}
	artifact.Hash, err = audit.HashArtifact(artifact)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if err := audit.AppendLog(f.Name(), artifact); err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := audit.VerifyChain(f.Name()); err != nil {
		t.Fatalf("verify: %v", err)
	}

	pub, priv, err := audit.GenerateSigningKeypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	signed, err := audit.SignArtifact(artifact, "soc-admin", pub, priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := audit.VerifySignedArtifact(signed); err != nil {
		t.Fatalf("verify signed: %v", err)
	}
}

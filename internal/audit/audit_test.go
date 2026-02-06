package audit

import (
	"os"
	"testing"
	"time"
)

func TestAuditChain(t *testing.T) {
	f, err := os.CreateTemp("", "audit-*.log")
	if err != nil {
		t.Fatalf("temp: %v", err)
	}
	defer func() { _ = os.Remove(f.Name()) }()
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	a1 := Artifact{ID: "1", CreatedAt: time.Now().UTC(), Summary: "s1"}
	h1, err := HashArtifact(a1)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	a1.Hash = h1
	if err := AppendLog(f.Name(), a1); err != nil {
		t.Fatalf("append: %v", err)
	}

	prev, err := LoadLastHash(f.Name())
	if err != nil {
		t.Fatalf("last hash: %v", err)
	}
	a2 := Artifact{ID: "2", CreatedAt: time.Now().UTC(), Summary: "s2", PrevHash: prev}
	h2, err := HashArtifact(a2)
	if err != nil {
		t.Fatalf("hash2: %v", err)
	}
	a2.Hash = h2
	if err := AppendLog(f.Name(), a2); err != nil {
		t.Fatalf("append2: %v", err)
	}

	if err := VerifyChain(f.Name()); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

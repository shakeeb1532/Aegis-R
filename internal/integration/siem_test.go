package integration

import (
	"os"
	"testing"
	"time"

	"aegisr/internal/core"
)

func TestExportSIEM(t *testing.T) {
	f, err := os.CreateTemp("", "siem-*.json")
	if err != nil {
		t.Fatalf("temp: %v", err)
	}
	defer func() { _ = os.Remove(f.Name()) }()
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	out := core.Output{GeneratedAt: time.Now().UTC(), Summary: "s", Findings: []string{"f1"}, NextMoves: []string{"n1"}}
	if err := ExportSIEM(f.Name(), out); err != nil {
		t.Fatalf("export: %v", err)
	}
}

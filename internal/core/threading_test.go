package core

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"aman/internal/env"
	"aman/internal/logic"
	"aman/internal/model"
	"aman/internal/state"
	"aman/internal/testutil"
)

func TestSyntheticThreadingSuite(t *testing.T) {
	root := testutil.RepoRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "data", "synthetic_threads.json"))
	if err != nil {
		t.Fatalf("read synthetic threads: %v", err)
	}
	var events []model.Event
	if err := json.Unmarshal(data, &events); err != nil {
		t.Fatalf("decode synthetic threads: %v", err)
	}
	environment, err := env.Load(filepath.Join(root, "data", "env.json"))
	if err != nil {
		t.Fatalf("env load: %v", err)
	}
	out := Assess(events, logic.DefaultRules(), environment, state.New())
	if len(out.State.Threads) < 3 {
		t.Fatalf("expected at least 3 threads, got %d", len(out.State.Threads))
	}
	confident := 0
	for _, tinfo := range out.State.Threads {
		if tinfo.Confidence >= 0.7 {
			confident++
		}
	}
	if confident < 3 {
		t.Fatalf("expected >=3 confident threads, got %d", confident)
	}
}

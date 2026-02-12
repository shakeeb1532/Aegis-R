package eval

import (
	"path/filepath"
	"testing"

	"aman/internal/logic"
	"aman/internal/testutil"
)

func TestRealisticScenarios(t *testing.T) {
	rules := logic.DefaultRules()
	root := testutil.RepoRoot(t)
	scenarios, err := LoadScenarios(filepath.Join(root, "data", "scenarios_realistic.json"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	rep := Score(scenarios, rules)
	if rep.Total == 0 {
		t.Fatalf("expected labels")
	}
	if rep.Accuracy < 0.75 {
		t.Fatalf("expected accuracy >= 0.75, got %.2f", rep.Accuracy)
	}
}

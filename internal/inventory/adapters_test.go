package inventory

import (
	"path/filepath"
	"testing"

	"aman/internal/testutil"
)

func TestAdapterConfigLoad(t *testing.T) {
	root := testutil.RepoRoot(t)
	cfg, err := LoadConfig(filepath.Join(root, "data", "inventory", "config.json"))
	if err == nil {
		if cfg.AWS.Region == "" {
			t.Fatalf("expected aws region")
		}
	}
}

func TestAdapterRegistry(t *testing.T) {
	_, err := NewAdapter("aws")
	if err != nil {
		t.Fatalf("expected aws adapter")
	}
	_, err = NewAdapter("unknown")
	if err == nil {
		t.Fatalf("expected error for unknown adapter")
	}
}

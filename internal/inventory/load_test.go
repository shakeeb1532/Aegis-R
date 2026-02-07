package inventory

import (
	"path/filepath"
	"testing"

	"aegisr/internal/testutil"
)

func TestLoadInventoryDir(t *testing.T) {
	root := testutil.RepoRoot(t)
	inv, err := Load(filepath.Join(root, "data", "inventory"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	env := BuildEnvironment(inv)
	if len(env.Hosts) == 0 {
		t.Fatalf("expected hosts")
	}
	if len(env.Identities) == 0 {
		t.Fatalf("expected identities")
	}
	if len(env.TrustBoundaries) == 0 {
		t.Fatalf("expected trust boundaries")
	}
}

func TestLoadInventoryFile(t *testing.T) {
	root := testutil.RepoRoot(t)
	inv, err := Load(filepath.Join(root, "data", "inventory", "aws.json"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(inv.AWS.Instances) == 0 {
		t.Fatalf("expected aws instances")
	}
}

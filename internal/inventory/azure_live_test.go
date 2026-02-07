package inventory

import (
	"errors"
	"testing"
)

func TestAzurePermissionErr(t *testing.T) {
	if !isAzurePermissionErr(errors.New("azure http 403")) {
		t.Fatalf("expected permission err")
	}
}

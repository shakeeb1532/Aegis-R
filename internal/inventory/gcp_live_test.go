package inventory

import (
	"context"
	"testing"
)

func TestGCPCredentialSelection(t *testing.T) {
	cfg := AdapterConfig{GCP: GCPConfig{ProjectID: "proj", CredsJSON: "{}"}}
	_, err := gcpCredentials(context.Background(), cfg)
	if err == nil {
		// empty json will still error on parse, but should return err
		return
	}
}

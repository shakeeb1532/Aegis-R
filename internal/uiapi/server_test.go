package uiapi

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"aman/internal/approval"
)

func TestGovernanceDualApprovalVisibility(t *testing.T) {
	tmp := t.TempDir()
	approvalsPath := filepath.Join(tmp, "approvals.log")
	pub1, priv1, err := approval.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	pub2, priv2, err := approval.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	a1, err := approval.SignAt("R-100", 10*time.Minute, true, "alice", "approver", pub1, priv1, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	a2, err := approval.SignAt("R-100", 10*time.Minute, true, "bob", "approver", pub2, priv2, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(approvalsPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		t.Fatal(err)
	}
	enc := json.NewEncoder(f)
	if err := enc.Encode(a1); err != nil {
		t.Fatal(err)
	}
	if err := enc.Encode(a2); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	s := NewServer("", "", approvalsPath)
	req := httptest.NewRequest("GET", "/api/governance", nil)
	w := httptest.NewRecorder()
	s.handleGovernance(w, req)
	if w.Code != 200 {
		t.Fatalf("status code %d", w.Code)
	}
	var items []ApprovalItem
	if err := json.Unmarshal(w.Body.Bytes(), &items); err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(items))
	}
	if !items[0].DualApproved || items[0].ValidSigners != 2 {
		t.Fatalf("unexpected governance status: %+v", items[0])
	}
}

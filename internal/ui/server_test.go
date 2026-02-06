package ui

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestUIAuthRequiresBasic(t *testing.T) {
	kp := `{"public_key":"cHVibGlj","private_key":"cHJpdmF0ZQ=="}`
	f, err := os.CreateTemp("", "kp-*.json")
	if err != nil {
		t.Fatalf("temp: %v", err)
	}
	defer func() { _ = os.Remove(f.Name()) }()
	if _, err := f.WriteString(kp); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	s, err := NewServer("", "", "", "", "", "", f.Name(), "user", "pass")
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	s.Routes().ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

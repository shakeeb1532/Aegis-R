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
	defer os.Remove(f.Name())
	f.WriteString(kp)
	f.Close()

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

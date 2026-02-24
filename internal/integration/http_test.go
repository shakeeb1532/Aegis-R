package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestHealthHandler(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	HealthHandler(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !bytes.Contains(w.Body.Bytes(), []byte(`"status":"ok"`)) {
		t.Fatalf("expected json health body")
	}
}

func TestIngestHandlerRequiresAPIKeyWhenConfigured(t *testing.T) {
	t.Setenv("AMAN_INGEST_API_KEY", "secret")
	req := httptest.NewRequest(http.MethodPost, "/ingest?schema=native", bytes.NewBufferString(`[]`))
	w := httptest.NewRecorder()
	IngestHandler(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestIngestHandlerSuccessWithAPIKey(t *testing.T) {
	t.Setenv("AMAN_INGEST_API_KEY", "secret")
	req := httptest.NewRequest(http.MethodPost, "/ingest?schema=native", bytes.NewBufferString(`[]`))
	req.Header.Set("X-API-Key", "secret")
	w := httptest.NewRecorder()
	IngestHandler(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
	}
	var got map[string]int
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["count"] != 0 {
		t.Fatalf("expected count=0")
	}
}

func TestIngestHandlerPayloadTooLarge(t *testing.T) {
	old := os.Getenv("AMAN_INGEST_API_KEY")
	t.Cleanup(func() { _ = os.Setenv("AMAN_INGEST_API_KEY", old) })
	_ = os.Unsetenv("AMAN_INGEST_API_KEY")

	payload := bytes.Repeat([]byte("a"), int(defaultIngestMaxBytes)+1)
	req := httptest.NewRequest(http.MethodPost, "/ingest?schema=native", bytes.NewReader(payload))
	w := httptest.NewRecorder()
	IngestHandler(w, req)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", w.Code)
	}
}

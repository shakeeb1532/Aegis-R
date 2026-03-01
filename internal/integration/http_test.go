package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthHandler(t *testing.T) {
	SetIngestConfig(IngestConfig{RequireAPIKey: false, Strict: false})
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
	SetIngestConfig(IngestConfig{RequireAPIKey: true, APIKey: "secret", Strict: false})
	req := httptest.NewRequest(http.MethodPost, "/ingest?schema=native", bytes.NewBufferString(`[]`))
	w := httptest.NewRecorder()
	IngestHandler(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestIngestHandlerSuccessWithAPIKey(t *testing.T) {
	SetIngestConfig(IngestConfig{RequireAPIKey: true, APIKey: "secret", Strict: true})
	payload := `[{"id":"e1","time":"2026-02-27T00:00:00Z","host":"host-1","user":"alice","type":"signin_attempt","details":{"signInId":"s1"}}]`
	req := httptest.NewRequest(http.MethodPost, "/ingest?schema=native", bytes.NewBufferString(payload))
	req.Header.Set("X-API-Key", "secret")
	w := httptest.NewRecorder()
	IngestHandler(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
	}
	var got struct {
		Data struct {
			Count int `json:"count"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Data.Count != 1 {
		t.Fatalf("expected count=1")
	}
}

func TestIngestHandlerPayloadTooLarge(t *testing.T) {
	SetIngestConfig(IngestConfig{RequireAPIKey: false, Strict: false})

	payload := bytes.Repeat([]byte("a"), int(defaultIngestMaxBytes)+1)
	req := httptest.NewRequest(http.MethodPost, "/ingest?schema=native", bytes.NewReader(payload))
	w := httptest.NewRecorder()
	IngestHandler(w, req)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", w.Code)
	}
}

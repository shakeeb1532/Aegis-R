package integration

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"

	"aman/internal/logic"
	"aman/internal/model"
)

type IngestResponse struct {
	Count int `json:"count"`
}

const defaultIngestMaxBytes int64 = 10 << 20 // 10 MiB

type errorResponse struct {
	Error string `json:"error"`
}

func IngestHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	if !isAuthorizedIngestRequest(r) {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	schema := r.URL.Query().Get("schema")
	if schema == "" {
		schema = string(SchemaNative)
	}
	kind := r.URL.Query().Get("kind")
	r.Body = http.MaxBytesReader(w, r.Body, defaultIngestMaxBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeJSONError(w, http.StatusRequestEntityTooLarge, "payload_too_large")
			return
		}
		writeJSONError(w, http.StatusBadRequest, "read_error")
		return
	}
	events, err := IngestEvents(body, IngestOptions{Schema: Schema(schema), Kind: kind})
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "schema_mapping_error: "+err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(IngestResponse{Count: len(events)})
}

func HealthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	rules := logic.DefaultRules()
	if len(rules) == 0 {
		writeJSONError(w, http.StatusServiceUnavailable, "rules_unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status": "ok",
		"rules":  len(rules),
	})
}

// Helper for native ingestion without HTTP
func IngestNative(events []model.Event) ([]model.Event, error) {
	out := make([]model.Event, len(events))
	copy(out, events)
	return out, nil
}

func isAuthorizedIngestRequest(r *http.Request) bool {
	expected := os.Getenv("AMAN_INGEST_API_KEY")
	if expected == "" {
		return true
	}
	return r.Header.Get("X-API-Key") == expected
}

func writeJSONError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(errorResponse{Error: msg})
}

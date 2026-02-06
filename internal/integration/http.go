package integration

import (
	"encoding/json"
	"io"
	"net/http"

	"aegisr/internal/model"
)

type IngestResponse struct {
	Count int `json:"count"`
}

func IngestHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	schema := r.URL.Query().Get("schema")
	if schema == "" {
		schema = string(SchemaNative)
	}
	kind := r.URL.Query().Get("kind")
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	events, err := IngestEvents(body, IngestOptions{Schema: Schema(schema), Kind: kind})
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	_ = json.NewEncoder(w).Encode(IngestResponse{Count: len(events)})
}

func HealthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// Helper for native ingestion without HTTP
func IngestNative(events []model.Event) ([]model.Event, error) {
	data, err := json.Marshal(events)
	if err != nil {
		return nil, err
	}
	return IngestEvents(data, IngestOptions{Schema: SchemaNative})
}

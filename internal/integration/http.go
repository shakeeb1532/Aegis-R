package integration

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"aman/internal/logic"
	"aman/internal/model"
)

type IngestResponse struct {
	Count int `json:"count"`
}

const defaultIngestMaxBytes int64 = 10 << 20 // 10 MiB

type IngestStats struct {
	start          time.Time
	totalRequests  uint64
	success        uint64
	failures       uint64
	unauthorized   uint64
	payloadTooLarge uint64
	readErrors     uint64
	schemaErrors   uint64
	eventsIn       uint64
	mappingMisses  uint64
	unmatchedReqs  uint64
}

type IngestSnapshot struct {
	UptimeSeconds   int64   `json:"uptime_seconds"`
	TotalRequests   uint64  `json:"total_requests"`
	Success         uint64  `json:"success"`
	Failures        uint64  `json:"failures"`
	Unauthorized    uint64  `json:"unauthorized"`
	PayloadTooLarge uint64  `json:"payload_too_large"`
	ReadErrors      uint64  `json:"read_errors"`
	SchemaErrors    uint64  `json:"schema_errors"`
	EventsIn        uint64  `json:"events_in"`
	MappingMisses   uint64  `json:"mapping_misses"`
	UnmatchedReqs   uint64  `json:"unmatched_requests"`
	FailureRate     float64 `json:"failure_rate"`
}

var (
	defaultIngestStats = &IngestStats{start: time.Now()}
	reqTypeOnce        sync.Once
	reqTypeSet         map[string]bool
)

func ingestSnapshot(stats *IngestStats) IngestSnapshot {
	total := atomic.LoadUint64(&stats.totalRequests)
	failures := atomic.LoadUint64(&stats.failures)
	rate := 0.0
	if total > 0 {
		rate = float64(failures) / float64(total)
	}
	return IngestSnapshot{
		UptimeSeconds:   int64(time.Since(stats.start).Seconds()),
		TotalRequests:   total,
		Success:         atomic.LoadUint64(&stats.success),
		Failures:        failures,
		Unauthorized:    atomic.LoadUint64(&stats.unauthorized),
		PayloadTooLarge: atomic.LoadUint64(&stats.payloadTooLarge),
		ReadErrors:      atomic.LoadUint64(&stats.readErrors),
		SchemaErrors:    atomic.LoadUint64(&stats.schemaErrors),
		EventsIn:        atomic.LoadUint64(&stats.eventsIn),
		MappingMisses:   atomic.LoadUint64(&stats.mappingMisses),
		UnmatchedReqs:   atomic.LoadUint64(&stats.unmatchedReqs),
		FailureRate:     rate,
	}
}

type errorResponse struct {
	Error string `json:"error"`
}

func IngestHandler(w http.ResponseWriter, r *http.Request) {
	atomic.AddUint64(&defaultIngestStats.totalRequests, 1)
	if r.Method != http.MethodPost {
		atomic.AddUint64(&defaultIngestStats.failures, 1)
		writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	if !isAuthorizedIngestRequest(r) {
		atomic.AddUint64(&defaultIngestStats.unauthorized, 1)
		atomic.AddUint64(&defaultIngestStats.failures, 1)
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
			atomic.AddUint64(&defaultIngestStats.payloadTooLarge, 1)
			atomic.AddUint64(&defaultIngestStats.failures, 1)
			writeJSONError(w, http.StatusRequestEntityTooLarge, "payload_too_large")
			return
		}
		atomic.AddUint64(&defaultIngestStats.readErrors, 1)
		atomic.AddUint64(&defaultIngestStats.failures, 1)
		writeJSONError(w, http.StatusBadRequest, "read_error")
		return
	}
	events, err := IngestEvents(body, IngestOptions{Schema: Schema(schema), Kind: kind})
	if err != nil {
		atomic.AddUint64(&defaultIngestStats.schemaErrors, 1)
		atomic.AddUint64(&defaultIngestStats.failures, 1)
		writeJSONError(w, http.StatusBadRequest, "schema_mapping_error: "+err.Error())
		return
	}
	atomic.AddUint64(&defaultIngestStats.success, 1)
	atomic.AddUint64(&defaultIngestStats.eventsIn, uint64(len(events)))
	trackMappingMisses(events)
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

func MetricsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(ingestSnapshot(defaultIngestStats))
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

func trackMappingMisses(events []model.Event) {
	reqTypeOnce.Do(func() {
		reqTypeSet = map[string]bool{}
		for _, rule := range logic.DefaultRules() {
			for _, req := range rule.Requirements {
				if req.Type != "" {
					reqTypeSet[req.Type] = true
				}
			}
		}
	})
	misses := 0
	for _, ev := range events {
		if ev.Type == "" {
			misses++
			continue
		}
		if !reqTypeSet[ev.Type] {
			misses++
		}
	}
	if misses > 0 {
		atomic.AddUint64(&defaultIngestStats.mappingMisses, uint64(misses))
		atomic.AddUint64(&defaultIngestStats.unmatchedReqs, 1)
	}
}

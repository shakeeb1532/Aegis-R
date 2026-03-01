package integration

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
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

type IngestConfig struct {
	RequireAPIKey bool
	APIKey        string
	MaxBytes      int64
	Strict        bool
}

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
	ingestConfig       = IngestConfig{
		RequireAPIKey: false,
		APIKey:        "",
		MaxBytes:      defaultIngestMaxBytes,
		Strict:        true,
	}
)

func SetIngestConfig(cfg IngestConfig) {
	if cfg.MaxBytes <= 0 {
		cfg.MaxBytes = defaultIngestMaxBytes
	}
	ingestConfig = cfg
}

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
	Error errorBody `json:"error"`
}

type errorBody struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id"`
}

type responseMeta struct {
	RequestID string `json:"request_id"`
}

type ingestEnvelope struct {
	Data any          `json:"data"`
	Meta responseMeta `json:"meta"`
}

func IngestHandler(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	enableIngestCORS(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("X-Request-ID", reqID)
	atomic.AddUint64(&defaultIngestStats.totalRequests, 1)
	if r.Method != http.MethodPost {
		atomic.AddUint64(&defaultIngestStats.failures, 1)
		writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed", reqID)
		return
	}
	if !isAuthorizedIngestRequest(r) {
		atomic.AddUint64(&defaultIngestStats.unauthorized, 1)
		atomic.AddUint64(&defaultIngestStats.failures, 1)
		writeJSONError(w, http.StatusUnauthorized, "unauthorized", "api key missing or invalid", reqID)
		return
	}
	schema := r.URL.Query().Get("schema")
	if schema == "" {
		if headerSchema := r.Header.Get("X-Aman-Schema"); headerSchema != "" {
			schema = headerSchema
		} else {
			schema = string(SchemaNative)
		}
	}
	kind := r.URL.Query().Get("kind")
	if kind == "" {
		kind = r.Header.Get("X-Aman-Kind")
	}
	r.Body = http.MaxBytesReader(w, r.Body, ingestConfig.MaxBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			atomic.AddUint64(&defaultIngestStats.payloadTooLarge, 1)
			atomic.AddUint64(&defaultIngestStats.failures, 1)
			writeJSONError(w, http.StatusRequestEntityTooLarge, "payload_too_large", "payload too large", reqID)
			return
		}
		atomic.AddUint64(&defaultIngestStats.readErrors, 1)
		atomic.AddUint64(&defaultIngestStats.failures, 1)
		writeJSONError(w, http.StatusBadRequest, "read_error", "unable to read request body", reqID)
		return
	}
	events, err := IngestEvents(body, IngestOptions{Schema: Schema(schema), Kind: kind})
	if err != nil {
		atomic.AddUint64(&defaultIngestStats.schemaErrors, 1)
		atomic.AddUint64(&defaultIngestStats.failures, 1)
		writeJSONError(w, http.StatusBadRequest, "schema_mapping_error", err.Error(), reqID)
		return
	}
	if ingestConfig.Strict && !isStrictDisabled(r) {
		if err := ValidateEvents(events); err != nil {
			atomic.AddUint64(&defaultIngestStats.failures, 1)
			writeJSONError(w, http.StatusUnprocessableEntity, "invalid_event", err.Error(), reqID)
			return
		}
	}
	atomic.AddUint64(&defaultIngestStats.success, 1)
	atomic.AddUint64(&defaultIngestStats.eventsIn, uint64(len(events)))
	trackMappingMisses(events)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(ingestEnvelope{
		Data: IngestResponse{Count: len(events)},
		Meta: responseMeta{RequestID: reqID},
	})
}

func HealthHandler(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	enableIngestCORS(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("X-Request-ID", reqID)
	if ingestConfig.RequireAPIKey && !isAuthorizedIngestRequest(r) {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized", "api key missing or invalid", reqID)
		return
	}
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed", reqID)
		return
	}
	rules := logic.DefaultRules()
	if len(rules) == 0 {
		writeJSONError(w, http.StatusServiceUnavailable, "rules_unavailable", "rules unavailable", reqID)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(ingestEnvelope{
		Data: map[string]any{
			"status": "ok",
			"rules":  len(rules),
		},
		Meta: responseMeta{RequestID: reqID},
	})
}

func MetricsHandler(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	enableIngestCORS(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("X-Request-ID", reqID)
	if ingestConfig.RequireAPIKey && !isAuthorizedIngestRequest(r) {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized", "api key missing or invalid", reqID)
		return
	}
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed", reqID)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(ingestEnvelope{
		Data: ingestSnapshot(defaultIngestStats),
		Meta: responseMeta{RequestID: reqID},
	})
}

// Helper for native ingestion without HTTP
func IngestNative(events []model.Event) ([]model.Event, error) {
	out := make([]model.Event, len(events))
	copy(out, events)
	return out, nil
}

func isAuthorizedIngestRequest(r *http.Request) bool {
	if !ingestConfig.RequireAPIKey {
		return true
	}
	expected := ingestConfig.APIKey
	if expected == "" {
		return false
	}
	if r.Header.Get("X-API-Key") == expected {
		return true
	}
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ") == expected
	}
	return false
}

func writeJSONError(w http.ResponseWriter, code int, codeStr string, msg string, reqID string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(errorResponse{
		Error: errorBody{
			Code:      codeStr,
			Message:   msg,
			RequestID: reqID,
		},
	})
}

func enableIngestCORS(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key, X-Aman-Schema, X-Aman-Kind, X-Aman-Strict, X-Request-ID")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
}

func requestID(r *http.Request) string {
	if v := r.Header.Get("X-Request-ID"); v != "" {
		return v
	}
	return fmt.Sprintf("req-%d", time.Now().UTC().UnixNano())
}

func isStrictDisabled(r *http.Request) bool {
	if v := r.URL.Query().Get("strict"); strings.EqualFold(v, "false") || v == "0" {
		return true
	}
	if v := r.Header.Get("X-Aman-Strict"); strings.EqualFold(v, "false") || v == "0" {
		return true
	}
	return false
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

type SchemaList struct {
	Schemas []string `json:"schemas"`
}

func SchemasHandler(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	enableIngestCORS(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("X-Request-ID", reqID)
	if ingestConfig.RequireAPIKey && !isAuthorizedIngestRequest(r) {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized", "api key missing or invalid", reqID)
		return
	}
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed", reqID)
		return
	}
	list := SupportedSchemas()
	names := make([]string, 0, len(list))
	for _, s := range list {
		names = append(names, string(s))
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(ingestEnvelope{
		Data: SchemaList{Schemas: names},
		Meta: responseMeta{RequestID: reqID},
	})
}

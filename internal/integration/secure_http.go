package integration

import (
	"encoding/json"
	"io"
	"net/http"
	"sync/atomic"
	"time"

	"aegisr/internal/secureingest"
)

const maxSecureIngestBytes = 32 << 20

type SecureIngestStats struct {
	start        time.Time
	total        uint64
	success      uint64
	hmacFailures uint64
	decryptFails uint64
	schemaErrors uint64
	bytesIn      uint64
}

type SecureIngestSnapshot struct {
	UptimeSeconds   int64   `json:"uptime_seconds"`
	Total           uint64  `json:"total"`
	Success         uint64  `json:"success"`
	HMACFailures    uint64  `json:"hmac_failures"`
	DecryptFailures uint64  `json:"decrypt_failures"`
	SchemaErrors    uint64  `json:"schema_errors"`
	BytesIn         uint64  `json:"bytes_in"`
	FailureRate     float64 `json:"failure_rate"`
	HMACFailureRate float64 `json:"hmac_failure_rate"`
	DecryptFailRate float64 `json:"decrypt_failure_rate"`
	SchemaErrorRate float64 `json:"schema_error_rate"`
}

func NewSecureIngestStats() *SecureIngestStats {
	return &SecureIngestStats{start: time.Now()}
}

func (s *SecureIngestStats) snapshot() SecureIngestSnapshot {
	total := atomic.LoadUint64(&s.total)
	hmacFails := atomic.LoadUint64(&s.hmacFailures)
	decryptFails := atomic.LoadUint64(&s.decryptFails)
	schemaErrors := atomic.LoadUint64(&s.schemaErrors)
	failures := hmacFails + decryptFails + schemaErrors
	rate := 0.0
	hmacRate := 0.0
	decryptRate := 0.0
	schemaRate := 0.0
	if total > 0 {
		rate = float64(failures) / float64(total)
		hmacRate = float64(hmacFails) / float64(total)
		decryptRate = float64(decryptFails) / float64(total)
		schemaRate = float64(schemaErrors) / float64(total)
	}
	return SecureIngestSnapshot{
		UptimeSeconds:   int64(time.Since(s.start).Seconds()),
		Total:           total,
		Success:         atomic.LoadUint64(&s.success),
		HMACFailures:    hmacFails,
		DecryptFailures: decryptFails,
		SchemaErrors:    schemaErrors,
		BytesIn:         atomic.LoadUint64(&s.bytesIn),
		FailureRate:     rate,
		HMACFailureRate: hmacRate,
		DecryptFailRate: decryptRate,
		SchemaErrorRate: schemaRate,
	}
}

func SecureIngestHandler(stats *SecureIngestStats, opts []secureingest.Options) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		body := http.MaxBytesReader(w, r.Body, maxSecureIngestBytes)
		data, err := io.ReadAll(body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		atomic.AddUint64(&stats.total, 1)
		atomic.AddUint64(&stats.bytesIn, uint64(len(data)))
		payload, _, err := secureingest.UnpackWithKeyring(data, opts)
		if err != nil {
			switch err {
			case secureingest.ErrHMACVerify:
				atomic.AddUint64(&stats.hmacFailures, 1)
			case secureingest.ErrDecrypt, secureingest.ErrPayloadHash:
				atomic.AddUint64(&stats.decryptFails, 1)
			default:
				atomic.AddUint64(&stats.decryptFails, 1)
			}
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		schema := r.URL.Query().Get("schema")
		if schema == "" {
			schema = string(SchemaNative)
		}
		kind := r.URL.Query().Get("kind")
		events, err := IngestEvents(payload, IngestOptions{Schema: Schema(schema), Kind: kind})
		if err != nil {
			atomic.AddUint64(&stats.schemaErrors, 1)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		atomic.AddUint64(&stats.success, 1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(IngestResponse{Count: len(events)})
	}
}

func SecureIngestHealthHandler(stats *SecureIngestStats) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(stats.snapshot())
	}
}

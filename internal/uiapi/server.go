package uiapi

import (
	"bufio"
	"encoding/json"
	"net/http"
	"os"
	"time"
)

type Server struct {
	reportPath    string
	auditPath     string
	approvalsPath string
}

func NewServer(reportPath, auditPath, approvalsPath string) *Server {
	return &Server{reportPath: reportPath, auditPath: auditPath, approvalsPath: approvalsPath}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/api/overview", s.handleOverview)
	mux.HandleFunc("/api/reasoning", s.handleReasoning)
	mux.HandleFunc("/api/queue", s.handleQueue)
	mux.HandleFunc("/api/governance", s.handleGovernance)
	mux.HandleFunc("/api/audit", s.handleAudit)
	mux.HandleFunc("/api/evaluations", s.handleEvaluations)
	mux.HandleFunc("/api/graph", s.handleGraph)
	return withCORS(mux)
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleOverview(w http.ResponseWriter, _ *http.Request) {
	report, err := loadReport(s.reportPath)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, buildOverview(report))
}

func (s *Server) handleReasoning(w http.ResponseWriter, _ *http.Request) {
	report, err := loadReport(s.reportPath)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, buildReasoningItems(report))
}

func (s *Server) handleQueue(w http.ResponseWriter, _ *http.Request) {
	report, err := loadReport(s.reportPath)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, buildQueueItems(report))
}

func (s *Server) handleGovernance(w http.ResponseWriter, _ *http.Request) {
	items := []ApprovalItem{}
	file, err := os.Open(s.approvalsPath)
	if err == nil {
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			var item ApprovalItem
			if err := json.Unmarshal(scanner.Bytes(), &item); err == nil {
				items = append(items, item)
			}
		}
		_ = file.Close()
	}
	writeJSON(w, items)
}

func (s *Server) handleAudit(w http.ResponseWriter, _ *http.Request) {
	items := []AuditItem{}
	file, err := os.Open(s.auditPath)
	if err == nil {
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			var raw struct {
				ID        string `json:"id"`
				CreatedAt string `json:"created_at"`
				Summary   string `json:"summary"`
				Signer    string `json:"signer"`
			}
			if err := json.Unmarshal(scanner.Bytes(), &raw); err == nil {
				items = append(items, AuditItem{
					ID:        raw.ID,
					Timestamp: formatTime(raw.CreatedAt),
					Summary:   raw.Summary,
					Signer:    raw.Signer,
				})
			}
		}
		_ = file.Close()
	}
	writeJSON(w, items)
}

func (s *Server) handleEvaluations(w http.ResponseWriter, _ *http.Request) {
	items := []EvaluationItem{
		{Label: "Synthetic accuracy", Value: "0.887", Delta: "+0.012", Note: "106 labeled scenarios"},
		{Label: "Public dataset consistency", Value: "0.903", Delta: "+0.008", Note: "31 labeled events"},
		{Label: "Pilot impact (est.)", Value: "-42% triage", Delta: "est.", Note: "feasible vs impossible splits"},
	}
	writeJSON(w, items)
}

func (s *Server) handleGraph(w http.ResponseWriter, _ *http.Request) {
	report, err := loadReport(s.reportPath)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, buildGraph(report))
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, err error) {
	w.WriteHeader(http.StatusInternalServerError)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

func formatTime(input string) string {
	if input == "" {
		return ""
	}
	if t, err := time.Parse(time.RFC3339, input); err == nil {
		return t.Format("2006-01-02 15:04 UTC")
	}
	return input
}

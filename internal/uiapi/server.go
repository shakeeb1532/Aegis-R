package uiapi

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"aman/internal/approval"
	"aman/internal/ops"
)

type Server struct {
	reportPath    string
	auditPath     string
	approvalsPath string
	feedbackPath  string
	requireKey    bool
	apiKey        string
}

type ServerOptions struct {
	ReportPath    string
	AuditPath     string
	ApprovalsPath string
	FeedbackPath  string
	RequireKey    bool
	APIKey        string
}

func NewServer(opts ServerOptions) *Server {
	return &Server{
		reportPath:    opts.ReportPath,
		auditPath:     opts.AuditPath,
		approvalsPath: opts.ApprovalsPath,
		feedbackPath:  opts.FeedbackPath,
		requireKey:    opts.RequireKey,
		apiKey:        opts.APIKey,
	}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/v1/healthz", s.handleHealth)
	mux.HandleFunc("/v1/overview", s.handleOverview)
	mux.HandleFunc("/v1/reasoning", s.handleReasoning)
	mux.HandleFunc("/v1/decisions", s.handleDecisions)
	mux.HandleFunc("/v1/queue", s.handleQueue)
	mux.HandleFunc("/v1/governance", s.handleGovernance)
	mux.HandleFunc("/v1/audit", s.handleAudit)
	mux.HandleFunc("/v1/evaluations", s.handleEvaluations)
	mux.HandleFunc("/v1/graph", s.handleGraph)
	mux.HandleFunc("/v1/pilot-kpis", s.handlePilotKpis)
	mux.HandleFunc("/v1/feedback", s.handleFeedback)
	mux.HandleFunc("/v1/report", s.handleReport)

	// Deprecated v0 routes for backward compatibility.
	mux.HandleFunc("/api/overview", s.handleOverview)
	mux.HandleFunc("/api/reasoning", s.handleReasoning)
	mux.HandleFunc("/api/queue", s.handleQueue)
	mux.HandleFunc("/api/governance", s.handleGovernance)
	mux.HandleFunc("/api/audit", s.handleAudit)
	mux.HandleFunc("/api/evaluations", s.handleEvaluations)
	mux.HandleFunc("/api/graph", s.handleGraph)
	mux.HandleFunc("/api/pilot-kpis", s.handlePilotKpis)
	mux.HandleFunc("/api/feedback", s.handleFeedback)
	return s.withCORS(s.withAuth(mux))
}

func (s *Server) withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key, X-Request-ID")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) withAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/healthz") {
			next.ServeHTTP(w, r)
			return
		}
		if !s.authorized(r) {
			writeError(w, http.StatusUnauthorized, "unauthorized", "api key missing or invalid", requestID(r))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	reqID := setRequestID(w, r)
	report, err := loadReport(s.reportPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "report_unavailable", err.Error(), reqID)
		return
	}
	writeJSON(w, buildOverview(report), responseMeta{RequestID: reqID})
}

func (s *Server) handleReasoning(w http.ResponseWriter, r *http.Request) {
	reqID := setRequestID(w, r)
	report, err := loadReport(s.reportPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "report_unavailable", err.Error(), reqID)
		return
	}
	writeJSON(w, buildReasoningItems(report), responseMeta{RequestID: reqID})
}

func (s *Server) handleQueue(w http.ResponseWriter, r *http.Request) {
	reqID := setRequestID(w, r)
	report, err := loadReport(s.reportPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "report_unavailable", err.Error(), reqID)
		return
	}
	writeJSON(w, buildQueueItems(report), responseMeta{RequestID: reqID})
}

func (s *Server) handleGovernance(w http.ResponseWriter, r *http.Request) {
	reqID := setRequestID(w, r)
	items := []ApprovalItem{}
	file, err := os.Open(s.approvalsPath)
	if err == nil {
		type group struct {
			latest   approval.Approval
			signers  map[string]bool
			valid    int
			template string
		}
		type record struct {
			Approval   approval.Approval `json:"approval"`
			TemplateID string            `json:"template_id"`
		}
		groups := map[string]*group{}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Bytes()
			var wrapped record
			a := approval.Approval{}
			templateID := ""
			if err := json.Unmarshal(line, &wrapped); err == nil && wrapped.Approval.ID != "" {
				a = wrapped.Approval
				templateID = wrapped.TemplateID
			} else if err := json.Unmarshal(line, &a); err != nil || a.ID == "" {
				continue
			}
			g, ok := groups[a.ID]
			if !ok {
				g = &group{signers: map[string]bool{}}
				groups[a.ID] = g
			}
			g.latest = a
			if templateID != "" {
				g.template = templateID
			}
			if a.SignerID != "" {
				g.signers[a.SignerID] = true
			}
			if err := approval.Verify(a, false, time.Now().UTC()); err == nil && a.SignerID != "" {
				g.valid++
			}
		}
		_ = file.Close()
		for id, g := range groups {
			signers := make([]string, 0, len(g.signers))
			for s := range g.signers {
				signers = append(signers, s)
			}
			sort.Strings(signers)
			status := "pending_second_approval"
			dualApproved := g.valid >= 2
			if dualApproved {
				status = "dual_approved"
			} else if g.valid == 1 {
				status = "single_approved"
			}
			items = append(items, ApprovalItem{
				ID:            id,
				Scope:         id,
				Status:        status,
				Approver:      g.latest.SignerID,
				Approvers:     signers,
				Expires:       formatTime(g.latest.ExpiresAt.Format(time.RFC3339)),
				DualRequired:  2,
				ValidSigners:  g.valid,
				DualApproved:  dualApproved,
				OktaVerified:  g.latest.OktaVerified,
				HumanDecision: "human_signoff_required",
				TemplateID:    g.template,
			})
		}
		sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	}
	limit, offset := parsePagination(r, 200)
	total := len(items)
	items = paginate(items, limit, offset)
	writeJSON(w, items, responseMeta{RequestID: reqID, Total: total, Limit: limit, Offset: offset})
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	reqID := setRequestID(w, r)
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
	limit, offset := parsePagination(r, 200)
	total := len(items)
	items = paginate(items, limit, offset)
	writeJSON(w, items, responseMeta{RequestID: reqID, Total: total, Limit: limit, Offset: offset})
}

func (s *Server) handleEvaluations(w http.ResponseWriter, r *http.Request) {
	reqID := setRequestID(w, r)
	items := []EvaluationItem{
		{Label: "Synthetic accuracy", Value: "0.887", Delta: "+0.012", Note: "106 labeled scenarios"},
		{Label: "Public dataset consistency", Value: "0.903", Delta: "+0.008", Note: "31 labeled events"},
		{Label: "Pilot impact (est.)", Value: "-42% triage", Delta: "est.", Note: "feasible vs impossible splits"},
	}
	writeJSON(w, items, responseMeta{RequestID: reqID})
}

func (s *Server) handleGraph(w http.ResponseWriter, r *http.Request) {
	reqID := setRequestID(w, r)
	report, err := loadReport(s.reportPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "report_unavailable", err.Error(), reqID)
		return
	}
	writeJSON(w, buildGraph(report), responseMeta{RequestID: reqID})
}

func (s *Server) handlePilotKpis(w http.ResponseWriter, r *http.Request) {
	reqID := setRequestID(w, r)
	report, err := loadReport(s.reportPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "report_unavailable", err.Error(), reqID)
		return
	}
	writeJSON(w, buildPilotKpis(report), responseMeta{RequestID: reqID})
}

func (s *Server) handleFeedback(w http.ResponseWriter, r *http.Request) {
	reqID := setRequestID(w, r)
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST", reqID)
		return
	}
	if s.feedbackPath == "" {
		writeError(w, http.StatusServiceUnavailable, "feedback_disabled", "feedback storage not configured", reqID)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", "unable to read body", reqID)
		return
	}
	var payload FeedbackRequest
	if err := json.Unmarshal(body, &payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "unable to parse json", reqID)
		return
	}
	payload.AnalystLabel = strings.TrimSpace(payload.AnalystLabel)
	if payload.DecisionID == "" || payload.AnalystLabel == "" {
		writeError(w, http.StatusBadRequest, "missing_fields", "decision_id and analyst_label are required", reqID)
		return
	}
	switch payload.AnalystLabel {
	case "agree", "disagree", "need_more_context":
	default:
		writeError(w, http.StatusBadRequest, "invalid_label", "analyst_label must be agree|disagree|need_more_context", reqID)
		return
	}
	if !ops.IsSafePath(s.feedbackPath) {
		writeError(w, http.StatusBadRequest, "unsafe_path", "feedback path rejected", reqID)
		return
	}
	if err := os.MkdirAll(filepath.Dir(s.feedbackPath), 0755); err != nil {
		writeError(w, http.StatusInternalServerError, "io_error", err.Error(), reqID)
		return
	}
	record := map[string]any{
		"submitted_at":   time.Now().UTC().Format(time.RFC3339),
		"request_id":     reqID,
		"decision_id":    payload.DecisionID,
		"decision_title": payload.DecisionTitle,
		"verdict":        payload.Verdict,
		"reason_code":    payload.ReasonCode,
		"analyst_label":  payload.AnalystLabel,
		"comment":        payload.Comment,
		"user_agent":     r.UserAgent(),
		"remote_addr":    r.RemoteAddr,
	}
	line, err := json.Marshal(record)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "encode_error", err.Error(), reqID)
		return
	}
	f, err := os.OpenFile(s.feedbackPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "io_error", err.Error(), reqID)
		return
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		writeError(w, http.StatusInternalServerError, "io_error", err.Error(), reqID)
		return
	}
	writeJSON(w, map[string]string{"status": "ok"}, responseMeta{RequestID: reqID})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	reqID := setRequestID(w, r)
	writeJSON(w, map[string]string{"status": "ok"}, responseMeta{RequestID: reqID})
}

func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	reqID := setRequestID(w, r)
	report, err := loadReport(s.reportPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "report_unavailable", err.Error(), reqID)
		return
	}
	writeJSON(w, report, responseMeta{RequestID: reqID})
}

func (s *Server) handleDecisions(w http.ResponseWriter, r *http.Request) {
	reqID := setRequestID(w, r)
	report, err := loadReport(s.reportPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "report_unavailable", err.Error(), reqID)
		return
	}
	items := buildDecisionItems(report)
	items = filterDecisions(items, r)
	limit, offset := parsePagination(r, 200)
	total := len(items)
	items = paginate(items, limit, offset)
	writeJSON(w, items, responseMeta{RequestID: reqID, Total: total, Limit: limit, Offset: offset})
}

type responseMeta struct {
	RequestID string `json:"request_id"`
	Total     int    `json:"total,omitempty"`
	Limit     int    `json:"limit,omitempty"`
	Offset    int    `json:"offset,omitempty"`
}

type apiEnvelope struct {
	Data any          `json:"data"`
	Meta responseMeta `json:"meta"`
}

type errorEnvelope struct {
	Error errorBody `json:"error"`
}

type errorBody struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id"`
}

func writeJSON(w http.ResponseWriter, v any, meta responseMeta) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(apiEnvelope{Data: v, Meta: meta})
}

func writeError(w http.ResponseWriter, code int, errCode string, msg string, reqID string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Request-ID", reqID)
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(errorEnvelope{
		Error: errorBody{
			Code:      errCode,
			Message:   msg,
			RequestID: reqID,
		},
	})
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

func (s *Server) authorized(r *http.Request) bool {
	if !s.requireKey {
		return true
	}
	if s.apiKey == "" {
		return false
	}
	if r.Header.Get("X-API-Key") == s.apiKey {
		return true
	}
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ") == s.apiKey
	}
	return false
}

func requestID(r *http.Request) string {
	if v := r.Header.Get("X-Request-ID"); v != "" {
		return v
	}
	return fmt.Sprintf("req-%d", time.Now().UTC().UnixNano())
}

func setRequestID(w http.ResponseWriter, r *http.Request) string {
	id := requestID(r)
	w.Header().Set("X-Request-ID", id)
	return id
}

type DecisionItem struct {
	RuleID      string   `json:"rule_id"`
	Name        string   `json:"name"`
	Verdict     string   `json:"verdict"`
	Confidence  float64  `json:"confidence"`
	ReasonCode  string   `json:"reason_code"`
	Decision    string   `json:"decision_label"`
	ThreadID    string   `json:"thread_id"`
	Missing     []string `json:"missing_evidence"`
	Updated     string   `json:"updated"`
	Evidence    []string `json:"evidence"`
	Explanation string   `json:"explanation"`
}

func buildDecisionItems(r *reportFile) []DecisionItem {
	items := make([]DecisionItem, 0, len(r.Reasoning.Results))
	for _, res := range r.Reasoning.Results {
		items = append(items, DecisionItem{
			RuleID:      res.RuleID,
			Name:        res.Name,
			Verdict:     verdictFromResult(res.Feasible, res.PrecondOK, res.ReasonCode),
			Confidence:  res.Confidence,
			ReasonCode:  res.ReasonCode,
			Decision:    res.DecisionLabel,
			ThreadID:    res.ThreadID,
			Missing:     summarizeGaps(res.MissingEvidence),
			Updated:     latestTimestamp(r.GeneratedAt),
			Evidence:    summarizeEvidence(res.SupportingEventIDs),
			Explanation: res.Explanation,
		})
	}
	return items
}

func filterDecisions(items []DecisionItem, r *http.Request) []DecisionItem {
	verdict := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("verdict")))
	ruleID := strings.TrimSpace(r.URL.Query().Get("rule_id"))
	threadID := strings.TrimSpace(r.URL.Query().Get("thread_id"))
	minConf := parseFloatQuery(r, "confidence_min")
	maxConf := parseFloatQuery(r, "confidence_max")
	out := items[:0]
	for _, item := range items {
		if verdict != "" && strings.ToUpper(item.Verdict) != verdict {
			continue
		}
		if ruleID != "" && !strings.EqualFold(item.RuleID, ruleID) {
			continue
		}
		if threadID != "" && !strings.EqualFold(item.ThreadID, threadID) {
			continue
		}
		if !minConf.isUnset && item.Confidence < minConf.value {
			continue
		}
		if !maxConf.isUnset && item.Confidence > maxConf.value {
			continue
		}
		out = append(out, item)
	}
	return out
}

type floatQuery struct {
	value   float64
	isUnset bool
}

func parseFloatQuery(r *http.Request, key string) floatQuery {
	raw := strings.TrimSpace(r.URL.Query().Get(key))
	if raw == "" {
		return floatQuery{isUnset: true}
	}
	f, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return floatQuery{isUnset: true}
	}
	return floatQuery{value: f}
}

func parsePagination(r *http.Request, defaultLimit int) (int, int) {
	limit := defaultLimit
	offset := 0
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}
	return limit, offset
}

func paginate[T any](items []T, limit int, offset int) []T {
	if offset >= len(items) {
		return []T{}
	}
	end := offset + limit
	if end > len(items) {
		end = len(items)
	}
	return items[offset:end]
}

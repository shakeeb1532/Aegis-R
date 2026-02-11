package ui

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"html/template"
	"math"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"aegisr/internal/approval"
	"aegisr/internal/audit"
	"aegisr/internal/governance"
	"aegisr/internal/model"
	"aegisr/internal/ops"
	"aegisr/internal/state"
)

type Server struct {
	AuditPath         string
	ApprovalsPath     string
	SignedAuditPath   string
	ReportPath        string
	ProfilesPath      string
	DisagreementsPath string
	Keypair           keypair
	BasicUser         string
	BasicPass         string
	Sessions          map[string]string
	Mu                sync.Mutex
	Approvals         []ApprovalRecord
	Profiles          []governance.AnalystProfile
	Disagreements     []governance.Disagreement
}

type Suggestion struct {
	RuleID      string
	Name        string
	Confidence  float64
	Score       float64
	Explanation string
	EvidenceIDs []string
}

type keypair struct {
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
}

func NewServer(auditPath string, approvalsPath string, signedAuditPath string, reportPath string, profilesPath string, disagreementsPath string, keypairPath string, basicUser string, basicPass string) (*Server, error) {
	kp := keypair{}
	if keypairPath != "" {
		if !ops.IsSafePath(keypairPath) {
			return nil, os.ErrInvalid
		}
		//nolint:gosec // path validated via IsSafePath
		// #nosec G304
		data, err := os.ReadFile(keypairPath)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(data, &kp); err != nil {
			return nil, err
		}
	} else {
		return nil, errors.New("keypair required for approvals")
	}
	approvals, _ := loadApprovals(approvalsPath)
	profiles, _ := loadProfiles(profilesPath)
	disagreements, _ := loadDisagreements(disagreementsPath)
	return &Server{
		AuditPath:         auditPath,
		ApprovalsPath:     approvalsPath,
		SignedAuditPath:   signedAuditPath,
		ReportPath:        reportPath,
		ProfilesPath:      profilesPath,
		DisagreementsPath: disagreementsPath,
		Keypair:           kp,
		BasicUser:         basicUser,
		BasicPass:         basicPass,
		Sessions:          map[string]string{},
		Approvals:         approvals,
		Profiles:          profiles,
		Disagreements:     disagreements,
	}, nil
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/login/ssostub", s.ssoStub)
	mux.HandleFunc("/", s.auth(s.overview))
	mux.HandleFunc("/overview", s.auth(s.overview))
	mux.HandleFunc("/attack-graph", s.auth(s.attackGraph))
	mux.HandleFunc("/reasoning", s.auth(s.reasoning))
	mux.HandleFunc("/queue", s.auth(s.queue))
	mux.HandleFunc("/governance", s.auth(s.governance))
	mux.HandleFunc("/audit", s.auth(s.audit))
	mux.HandleFunc("/tickets", s.auth(s.tickets))
	mux.HandleFunc("/evaluations", s.auth(s.evaluations))
	mux.HandleFunc("/approve", s.auth(s.approve))
	mux.HandleFunc("/disagree", s.auth(s.disagree))
	mux.HandleFunc("/download", s.auth(s.download))
	return mux
}

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.basicOK(r) || s.sessionOK(r) {
			next(w, r)
			return
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="Aegis-R"`)
		w.WriteHeader(http.StatusUnauthorized)
	}
}

func (s *Server) basicOK(r *http.Request) bool {
	if s.BasicUser == "" {
		return false
	}
	u, p, ok := r.BasicAuth()
	return ok && u == s.BasicUser && p == s.BasicPass
}

func (s *Server) sessionOK(r *http.Request) bool {
	cookie, err := r.Cookie("aegis_session")
	if err != nil {
		return false
	}
	s.Mu.Lock()
	defer s.Mu.Unlock()
	_, ok := s.Sessions[cookie.Value]
	return ok
}

func (s *Server) ssoStub(w http.ResponseWriter, r *http.Request) {
	user := r.URL.Query().Get("user")
	if user == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	tok := randomToken()
	s.Mu.Lock()
	s.Sessions[tok] = user
	s.Mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "aegis_session", Value: tok, Path: "/", HttpOnly: true})
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (s *Server) overview(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "overview")
}

func (s *Server) attackGraph(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "attack-graph")
}

func (s *Server) reasoning(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "reasoning")
}

func (s *Server) queue(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "queue")
}

func (s *Server) governance(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "governance")
}

func (s *Server) audit(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "audit")
}

func (s *Server) evaluations(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "evaluations")
}

func (s *Server) tickets(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "tickets")
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, page string) {
	artifacts, _ := loadArtifacts(s.AuditPath)
	signed, _ := loadSignedArtifacts(s.SignedAuditPath)
	report, _ := loadReport(s.ReportPath)
	s.Mu.Lock()
	approvals := make([]ApprovalRecord, len(s.Approvals))
	copy(approvals, s.Approvals)
	profiles := make([]governance.AnalystProfile, len(s.Profiles))
	copy(profiles, s.Profiles)
	disagreements := make([]governance.Disagreement, len(s.Disagreements))
	copy(disagreements, s.Disagreements)
	s.Mu.Unlock()
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	ticketID := strings.TrimSpace(r.URL.Query().Get("ticket"))
	if q != "" {
		artifacts = filterArtifacts(artifacts, q)
		approvals = filterApprovals(approvals, q)
		signed = filterSigned(signed, q)
	}
	type RuleView struct {
		Rule      model.RuleResult
		Status    string
		GapCount  int
		HasGaps   bool
		HasEvents bool
	}
	// Suggestion is defined at top-level for reuse
	ruleViews := make([]RuleView, 0, len(report.Reasoning.Results))
	statsTotal := len(report.Reasoning.Results)
	statsFeasible := 0
	statsGaps := 0
	avgConfidence := 0.0
	gapCounts := map[string]int{}
	for _, rr := range report.Reasoning.Results {
		status := "incomplete"
		if rr.Feasible && len(rr.MissingEvidence) == 0 {
			status = "feasible"
		} else if !rr.Feasible && len(rr.MissingEvidence) == 0 {
			status = "impossible"
		}
		if rr.Feasible {
			statsFeasible++
		}
		if len(rr.MissingEvidence) > 0 {
			statsGaps++
			for _, m := range rr.MissingEvidence {
				gapCounts[m.Type]++
			}
		}
		avgConfidence += rr.Confidence
		ruleViews = append(ruleViews, RuleView{
			Rule:      rr,
			Status:    status,
			GapCount:  len(rr.MissingEvidence),
			HasGaps:   len(rr.MissingEvidence) > 0,
			HasEvents: len(rr.SupportingEventIDs) > 0,
		})
	}
	if statsTotal > 0 {
		avgConfidence = avgConfidence / float64(statsTotal)
	}
	type GapStat struct {
		Type  string
		Count int
	}
	gapStats := make([]GapStat, 0, len(gapCounts))
	for k, v := range gapCounts {
		gapStats = append(gapStats, GapStat{Type: k, Count: v})
	}
	sort.Slice(gapStats, func(i, j int) bool { return gapStats[i].Count > gapStats[j].Count })
	if len(gapStats) > 5 {
		gapStats = gapStats[:5]
	}
	statsInfeasible := 0
	if statsTotal >= statsFeasible {
		statsInfeasible = statsTotal - statsFeasible
	}
	confidencePercent := int(avgConfidence * 100)
	verdict := "incomplete"
	for _, rv := range ruleViews {
		if rv.Status == "impossible" {
			verdict = "impossible"
		}
		if rv.Status == "feasible" {
			verdict = "confirmed"
			break
		}
	}
	decayWindow := "24h"
	suggestions := buildSuggestions(report.Reasoning.Results, approvals)
	selectedTicket, ticketResults, ticketApprovals := selectTicket(report, approvals, ticketID)
	tmpl := template.Must(template.New("index").Parse(indexHTML))
	_ = tmpl.Execute(w, struct {
		Page            string
		Artifacts       []audit.Artifact
		Approvals       []ApprovalRecord
		ApprovalsByID   map[string]int
		DualCount       int
		Signed          []SignedStatus
		Report          ReportView
		RuleViews       []RuleView
		Suggestions     []Suggestion
		StatsTotal      int
		StatsFeasible   int
		StatsInfeasible int
		StatsGaps       int
		AvgConfidence   float64
		ConfidencePct   int
		Verdict         string
		DecayWindow     string
		TopGaps         []GapStat
		Profiles        []governance.AnalystProfile
		Disagreements   []governance.Disagreement
		Role            string
		AuditPath       string
		SignedAuditPath string
		Query           string
		TicketID        string
		SelectedTicket  state.Ticket
		TicketResults   []model.RuleResult
		TicketApprovals []ApprovalRecord
		GraphSVG        template.HTML
	}{
		Page:            page,
		Artifacts:       artifacts,
		Approvals:       approvals,
		ApprovalsByID:   countApprovals(approvals),
		DualCount:       countDualApprovals(approvals),
		Signed:          signed,
		Report:          report,
		RuleViews:       ruleViews,
		Suggestions:     suggestions,
		StatsTotal:      statsTotal,
		StatsFeasible:   statsFeasible,
		StatsInfeasible: statsInfeasible,
		StatsGaps:       statsGaps,
		AvgConfidence:   avgConfidence,
		ConfidencePct:   confidencePercent,
		Verdict:         verdict,
		DecayWindow:     decayWindow,
		TopGaps:         gapStats,
		Profiles:        profiles,
		Disagreements:   disagreements,
		Role:            s.currentRole(r),
		AuditPath:       s.AuditPath,
		SignedAuditPath: s.SignedAuditPath,
		Query:           q,
		TicketID:        ticketID,
		SelectedTicket:  selectedTicket,
		TicketResults:   ticketResults,
		TicketApprovals: ticketApprovals,
		GraphSVG:        buildGraphSVG(report.State.GraphOverlay.CurrentNodes, report.State.GraphOverlay.Reachable),
	})
}

func countApprovals(approvals []ApprovalRecord) map[string]int {
	out := map[string]int{}
	for _, a := range approvals {
		out[a.Approval.ID]++
	}
	return out
}

func countDualApprovals(approvals []ApprovalRecord) int {
	counts := countApprovals(approvals)
	dual := 0
	for _, c := range counts {
		if c >= 2 {
			dual++
		}
	}
	return dual
}

func buildGraphSVG(current []string, reachable []string) template.HTML {
	nodes := append([]string{}, current...)
	nodes = append(nodes, reachable...)
	if len(nodes) == 0 {
		return template.HTML("")
	}
	size := 420
	radius := 160
	cx := float64(size / 2)
	cy := float64(size / 2)
	angleStep := 360.0 / float64(len(nodes))
	var b strings.Builder
	b.WriteString(`<svg viewBox="0 0 420 420" width="100%" height="220" role="img" aria-label="attack graph">`)
	for i, n := range nodes {
		angle := (angleStep * float64(i)) * (3.14159 / 180.0)
		x := cx + float64(radius)*cos(angle)
		y := cy + float64(radius)*sin(angle)
		color := "#60a5fa"
		for _, c := range current {
			if c == n {
				color = "#4fd1c5"
				break
			}
		}
		b.WriteString(fmt.Sprintf(`<circle cx="%.1f" cy="%.1f" r="18" fill="rgba(15,22,32,0.9)" stroke="%s" stroke-width="2"></circle>`, x, y, color))
		b.WriteString(fmt.Sprintf(`<text x="%.1f" y="%.1f" text-anchor="middle" dominant-baseline="middle" font-size="10" fill="%s">%s</text>`, x, y, color, html.EscapeString(shortenLabel(n, 10))))
	}
	b.WriteString(`</svg>`)
	// #nosec G203 - HTML is constructed from controlled data
	return template.HTML(b.String())
}

func shortenLabel(v string, max int) string {
	if len(v) <= max {
		return v
	}
	return v[:max]
}

func sin(v float64) float64 { return math.Sin(v) }
func cos(v float64) float64 { return math.Cos(v) }

func selectTicket(report ReportView, approvals []ApprovalRecord, id string) (state.Ticket, []model.RuleResult, []ApprovalRecord) {
	if id == "" {
		return state.Ticket{}, nil, nil
	}
	var selected state.Ticket
	for _, t := range report.State.Tickets {
		if t.ID == id {
			selected = t
			break
		}
	}
	if selected.ID == "" {
		return state.Ticket{}, nil, nil
	}
	results := []model.RuleResult{}
	for _, r := range report.Reasoning.Results {
		if r.ThreadID == selected.ThreadID {
			results = append(results, r)
		}
	}
	relatedApprovals := []ApprovalRecord{}
	for _, a := range approvals {
		if a.Approval.ID == selected.ID || a.Approval.ID == selected.ThreadID {
			relatedApprovals = append(relatedApprovals, a)
		}
	}
	return selected, results, relatedApprovals
}

func (s *Server) approve(w http.ResponseWriter, r *http.Request) {
	curRole := s.currentRole(r)
	if curRole != "approver" && curRole != "admin" {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	id := r.FormValue("id")
	signer := r.FormValue("signer")
	role := r.FormValue("role")
	ttl := r.FormValue("ttl")
	rationale := r.FormValue("rationale")
	gaps := strings.Split(r.FormValue("gaps"), ",")
	if id == "" || signer == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	dur, _ := time.ParseDuration(ttl)
	if dur == 0 {
		dur = 10 * time.Minute
	}
	pubBytes, _ := base64.StdEncoding.DecodeString(s.Keypair.PublicKey)
	privBytes, _ := base64.StdEncoding.DecodeString(s.Keypair.PrivateKey)
	app, err := approval.Sign(id, dur, true, signer, role, pubBytes, privBytes)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if s.ApprovalsPath != "" {
		rec := ApprovalRecord{Approval: app, Rationale: rationale, EvidenceGaps: trimList(gaps)}
		if err := appendApproval(s.ApprovalsPath, rec); err == nil {
			s.Mu.Lock()
			s.Approvals = append(s.Approvals, rec)
			s.Mu.Unlock()
		}
	}
	data, _ := json.MarshalIndent(app, "", "  ")
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(data)
}

func (s *Server) disagree(w http.ResponseWriter, r *http.Request) {
	role := s.currentRole(r)
	if role == "auditor" {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	analyst := r.FormValue("analyst_id")
	rule := r.FormValue("rule_id")
	expected := r.FormValue("expected")
	actual := r.FormValue("actual")
	rationale := r.FormValue("rationale")
	if analyst == "" || rule == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	d := governance.Disagreement{
		AnalystID: analyst,
		RuleID:    rule,
		Expected:  expected,
		Actual:    actual,
		Rationale: rationale,
	}
	if s.DisagreementsPath != "" {
		if err := governance.AppendDisagreement(s.DisagreementsPath, d); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}
	s.Mu.Lock()
	s.Disagreements = append(s.Disagreements, d)
	s.Mu.Unlock()
	http.Redirect(w, r, "/queue", http.StatusFound)
}

func (s *Server) download(w http.ResponseWriter, r *http.Request) {
	kind := r.URL.Query().Get("type")
	if kind == "audit" {
		s.serveFile(w, s.AuditPath, "audit.log")
		return
	}
	if kind == "signed" {
		s.serveFile(w, s.SignedAuditPath, "signed_audit.log")
		return
	}
	if kind == "approvals" {
		s.serveFile(w, s.ApprovalsPath, "approvals.log")
		return
	}
	if kind == "ticket" {
		id := r.URL.Query().Get("id")
		if id == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		report, err := loadReport(s.ReportPath)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		var ticket *state.Ticket
		for i := range report.State.Tickets {
			if report.State.Tickets[i].ID == id {
				ticket = &report.State.Tickets[i]
				break
			}
		}
		if ticket == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		results := []model.RuleResult{}
		for _, r := range report.Reasoning.Results {
			if r.ThreadID == ticket.ThreadID {
				results = append(results, r)
			}
		}
		approvals := []ApprovalRecord{}
		s.Mu.Lock()
		for _, a := range s.Approvals {
			if a.Approval.ID == ticket.ID || a.Approval.ID == ticket.ThreadID {
				approvals = append(approvals, a)
			}
		}
		s.Mu.Unlock()
		payload := map[string]interface{}{
			"ticket":    ticket,
			"rules":     results,
			"approvals": approvals,
		}
		data, _ := json.MarshalIndent(payload, "", "  ")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=ticket.json")
		_, _ = w.Write(data)
		return
	}
	id := r.URL.Query().Get("id")
	s.Mu.Lock()
	defer s.Mu.Unlock()
	for _, a := range s.Approvals {
		if a.Approval.ID == id {
			data, _ := json.MarshalIndent(a.Approval, "", "  ")
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Disposition", "attachment; filename=approval.json")
			_, _ = w.Write(data)
			return
		}
	}
	w.WriteHeader(http.StatusNotFound)
}

func (s *Server) serveFile(w http.ResponseWriter, path string, name string) {
	if path == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if !ops.IsSafePath(path) {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	//nolint:gosec // path validated via IsSafePath
	// #nosec G304
	data, err := os.ReadFile(path)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename="+name)
	_, _ = w.Write(data)
}

func (s *Server) currentRole(r *http.Request) string {
	if s.BasicUser != "" {
		u, _, ok := r.BasicAuth()
		if ok {
			return roleForUser(u)
		}
	}
	cookie, err := r.Cookie("aegis_session")
	if err == nil {
		s.Mu.Lock()
		user := s.Sessions[cookie.Value]
		s.Mu.Unlock()
		return roleForUser(user)
	}
	return "analyst"
}

func roleForUser(user string) string {
	if strings.Contains(user, "admin") {
		return "admin"
	}
	if strings.Contains(user, "approver") {
		return "approver"
	}
	if strings.Contains(user, "auditor") {
		return "auditor"
	}
	return "analyst"
}

func trimList(in []string) []string {
	out := []string{}
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

func loadArtifacts(path string) ([]audit.Artifact, error) {
	if path == "" {
		return nil, nil
	}
	if !ops.IsSafePath(path) {
		return nil, os.ErrInvalid
	}
	//nolint:gosec // path validated via IsSafePath
	// #nosec G304
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	out := []audit.Artifact{}
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var a audit.Artifact
		if err := json.Unmarshal([]byte(line), &a); err != nil {
			continue
		}
		out = append(out, a)
	}
	return out, nil
}

func randomToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

func buildSuggestions(results []model.RuleResult, approvals []ApprovalRecord) []Suggestion {
	out := []Suggestion{}
	for _, r := range results {
		if len(r.MissingEvidence) > 0 {
			continue
		}
		if r.Confidence < 0.7 {
			continue
		}
		score := r.Confidence
		matches := 0
		for _, a := range approvals {
			if strings.Contains(a.Approval.ID, r.RuleID) || strings.Contains(a.Rationale, r.RuleID) {
				matches++
			}
		}
		if matches > 0 {
			score += 0.05 * float64(matches)
		}
		out = append(out, Suggestion{
			RuleID:      r.RuleID,
			Name:        r.Name,
			Confidence:  r.Confidence,
			Score:       score,
			Explanation: r.Explanation,
			EvidenceIDs: r.SupportingEventIDs,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	if len(out) > 5 {
		out = out[:5]
	}
	return out
}

const indexHTML = `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Aegis-R Review</title>
  <style>
    :root {
      --bg: #0b1015;
      --surface: #111821;
      --surface-2: #151f2b;
      --line: #223141;
      --ink: #e5eef7;
      --muted: #8fa3b8;
      --teal: #4fd1c5;
      --blue: #60a5fa;
      --amber: #f59e0b;
      --red: #f87171;
      --purple: #a78bfa;
      --shadow: 0 20px 40px rgba(0,0,0,0.35);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: "Sora", "Space Grotesk", system-ui, sans-serif;
      color: var(--ink);
      background: radial-gradient(circle at 15% 15%, #18212c 0, #0b1015 45%, #0a0f14 100%);
    }
    body::before {
      content: "";
      position: fixed;
      inset: 0;
      background: radial-gradient(circle at 80% 20%, rgba(79,209,197,0.08), transparent 35%),
                  radial-gradient(circle at 20% 80%, rgba(96,165,250,0.08), transparent 40%);
      pointer-events: none;
      z-index: -1;
    }
    .layout {
      display: grid;
      grid-template-columns: 260px 1fr;
      min-height: 100vh;
    }
    .sidebar {
      padding: 28px 18px;
      border-right: 1px solid var(--line);
      background: linear-gradient(180deg, #0f1620 0%, #0c1218 100%);
    }
    .content {
      display: flex;
      flex-direction: column;
    }
    .brand {
      display: grid;
      gap: 6px;
      margin-bottom: 18px;
    }
    .brand-title {
      font-size: 22px;
      letter-spacing: 0.04em;
      text-transform: uppercase;
      font-weight: 700;
    }
    .brand-sub {
      font-size: 12px;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: 0.2em;
    }
    .topbar {
      padding: 24px 36px 18px;
      border-bottom: 1px solid var(--line);
      background: linear-gradient(135deg, rgba(15,22,32,0.9) 0%, rgba(16,25,35,0.95) 50%, rgba(11,16,21,0.95) 100%);
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      flex-wrap: wrap;
    }
    .page-title {
      margin: 0;
      font-size: 30px;
      letter-spacing: -0.4px;
    }
    .page-sub {
      color: var(--muted);
      font-size: 13px;
      margin-top: 6px;
    }
    .role-chip {
      padding: 6px 12px;
      border-radius: 999px;
      background: rgba(167, 139, 250, 0.15);
      color: var(--purple);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      border: 1px solid rgba(167, 139, 250, 0.4);
    }
    .subtle { color: var(--muted); font-size: 14px; margin-top: 6px; }
    main { padding: 24px 36px 64px; }
    .grid {
      display: grid;
      gap: 18px;
      grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
      margin-bottom: 22px;
    }
    .card {
      background: linear-gradient(145deg, rgba(17,24,33,0.98) 0%, rgba(21,31,43,0.98) 100%);
      border: 1px solid var(--line);
      border-radius: 16px;
      box-shadow: var(--shadow);
      padding: 16px 18px;
    }
    .kpi {
      display: flex;
      flex-direction: column;
      gap: 6px;
    }
    .kpi .label { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.1em; }
    .kpi .value { font-size: 28px; font-weight: 600; color: var(--blue); }
    .kpi .trend { font-size: 12px; color: var(--muted); }
    .meter {
      height: 8px;
      border-radius: 999px;
      background: #0f1620;
      border: 1px solid var(--line);
      overflow: hidden;
      margin-top: 8px;
    }
    .meter span {
      display: block;
      height: 100%;
      background: linear-gradient(90deg, rgba(79,209,197,0.8), rgba(96,165,250,0.9));
    }
    .section-title {
      font-size: 20px;
      margin: 26px 0 12px;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .pill {
      padding: 2px 10px;
      border-radius: 999px;
      font-size: 12px;
      border: 1px solid var(--line);
      background: #0f1620;
      color: var(--muted);
    }
    .status {
      padding: 4px 10px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.08em;
    }
    .status.feasible { background: rgba(79,209,197,0.12); color: var(--teal); border: 1px solid rgba(79,209,197,0.4); }
    .status.incomplete { background: rgba(245,158,11,0.12); color: var(--amber); border: 1px solid rgba(245,158,11,0.45); }
    .status.impossible { background: rgba(248,113,113,0.12); color: var(--red); border: 1px solid rgba(248,113,113,0.45); }
    .status.govern { background: rgba(167,139,250,0.12); color: var(--purple); border: 1px solid rgba(167,139,250,0.45); }
    .status.label-suppress { background: rgba(148,163,184,0.12); color: var(--muted); border: 1px solid rgba(148,163,184,0.35); }
    .status.label-deprioritize { background: rgba(245,158,11,0.12); color: var(--amber); border: 1px solid rgba(245,158,11,0.45); }
    .status.label-keep { background: rgba(96,165,250,0.12); color: var(--blue); border: 1px solid rgba(96,165,250,0.4); }
    .status.label-escalate { background: rgba(248,113,113,0.12); color: var(--red); border: 1px solid rgba(248,113,113,0.45); }
    .search-bar { display: flex; gap: 10px; margin-top: 12px; }
    input, button, select {
      padding: 10px 12px;
      border-radius: 10px;
      border: 1px solid var(--line);
      font-size: 14px;
      background: #0f1620;
      color: var(--ink);
    }
    button { background: var(--teal); color: #071015; border: none; cursor: pointer; font-weight: 600; }
    button.secondary { background: #0f1620; color: var(--muted); border: 1px solid var(--line); }
    table { width: 100%; border-collapse: collapse; font-size: 14px; }
    th, td { padding: 10px 8px; border-bottom: 1px solid var(--line); text-align: left; color: var(--ink); }
    .timeline { display: grid; gap: 10px; }
    .timeline-item {
      display: flex;
      gap: 12px;
      padding: 12px;
      border: 1px solid var(--line);
      border-radius: 12px;
      background: var(--surface);
    }
    .timeline-item .time { font-weight: 600; min-width: 220px; }
    .tag { font-size: 12px; padding: 2px 8px; border-radius: 6px; background: rgba(96,165,250,0.2); color: var(--blue); }
    .rule-grid { display: grid; gap: 12px; }
    .rule-card { padding: 14px; border-radius: 14px; border: 1px solid var(--line); background: var(--surface-2); }
    .chip-row { display:flex; gap:8px; align-items:center; flex-wrap:wrap; margin-top:8px; }
    details summary { cursor: pointer; font-weight: 600; margin-bottom: 6px; }
    .muted { color: var(--muted); }
    .link-row { margin-top: 10px; display: flex; gap: 12px; flex-wrap: wrap; }
    a { color: var(--blue); text-decoration: none; }
    .approval-form { display: grid; gap: 10px; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); }
    .approval-form .full { grid-column: 1 / -1; }
    .footer-note { font-size: 12px; color: var(--muted); margin-top: 10px; }
    .side-nav {
      display: grid;
      gap: 8px;
      margin-top: 20px;
    }
    .side-nav a {
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.12em;
      padding: 10px 12px;
      border-radius: 10px;
      border: 1px solid transparent;
    }
    .side-nav a.active {
      color: var(--teal);
      border-color: rgba(79,209,197,0.4);
      background: rgba(79,209,197,0.08);
    }
    .sidebar-card {
      margin-top: 18px;
      padding: 12px;
      border-radius: 12px;
      border: 1px solid var(--line);
      background: #0f1620;
      font-size: 12px;
    }
    .sidebar-card strong { display: block; font-size: 16px; margin-top: 6px; }
    .section-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 16px;
    }
    .graph-canvas {
      margin-top: 16px;
      padding: 18px;
      border-radius: 14px;
      border: 1px solid var(--line);
      background: radial-gradient(circle at 30% 20%, rgba(96,165,250,0.08), transparent 40%), #0f1620;
      min-height: 220px;
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      align-items: flex-start;
    }
    .node {
      padding: 8px 12px;
      border-radius: 999px;
      font-size: 12px;
      border: 1px solid var(--line);
      background: #0b1218;
    }
    .node.current { border-color: rgba(79,209,197,0.6); color: var(--teal); }
    .node.reachable { border-color: rgba(96,165,250,0.5); color: var(--blue); }
    .list {
      display: grid;
      gap: 8px;
      margin: 0;
      padding: 0;
      list-style: none;
    }
    .list li {
      padding: 10px 12px;
      border: 1px solid var(--line);
      border-radius: 10px;
      background: #0f1620;
    }
    @media (max-width: 980px) {
      .layout { grid-template-columns: 1fr; }
      .sidebar { border-right: none; border-bottom: 1px solid var(--line); }
    }
    @media (max-width: 720px) {
      main { padding: 18px; }
      .topbar { padding: 18px; }
      .timeline-item { flex-direction: column; }
      .timeline-item .time { min-width: auto; }
    }
  </style>
</head>
<body>
  <div class="layout">
    <aside class="sidebar">
      <div class="brand">
        <div class="brand-title">Aegis-R</div>
        <div class="brand-sub">Reasoning First</div>
      </div>
      <div class="role-chip">Role: {{.Role}}</div>
      <div class="side-nav">
        <a class="{{if eq .Page "overview"}}active{{end}}" href="/overview">Overview</a>
        <a class="{{if eq .Page "attack-graph"}}active{{end}}" href="/attack-graph">Attack Graph</a>
        <a class="{{if eq .Page "reasoning"}}active{{end}}" href="/reasoning">Reasoning</a>
        <a class="{{if eq .Page "queue"}}active{{end}}" href="/queue">Queue</a>
        <a class="{{if eq .Page "governance"}}active{{end}}" href="/governance">Governance</a>
        <a class="{{if eq .Page "audit"}}active{{end}}" href="/audit">Audit</a>
        <a class="{{if eq .Page "tickets"}}active{{end}}" href="/tickets">Tickets</a>
        <a class="{{if eq .Page "evaluations"}}active{{end}}" href="/evaluations">Evaluations</a>
      </div>
      <div class="sidebar-card">
        <div class="muted">Current Verdict</div>
        <strong>{{.Verdict}}</strong>
        <div class="muted">Confidence {{printf "%.2f" .AvgConfidence}}</div>
        <div class="muted">Decay {{.DecayWindow}}</div>
      </div>
      <div class="sidebar-card">
        <div class="muted">Drift Signals</div>
        <strong>{{len .Report.DriftSignals}}</strong>
        <div class="muted">Evidence gaps {{.StatsGaps}}</div>
      </div>
    </aside>
    <div class="content">
      <header class="topbar">
        <div>
          {{if eq .Page "overview"}}<h1 class="page-title">Overview</h1>{{end}}
          {{if eq .Page "attack-graph"}}<h1 class="page-title">Attack Graph</h1>{{end}}
          {{if eq .Page "reasoning"}}<h1 class="page-title">Reasoning Panel</h1>{{end}}
          {{if eq .Page "queue"}}<h1 class="page-title">Reasoning Queue</h1>{{end}}
          {{if eq .Page "governance"}}<h1 class="page-title">Governance</h1>{{end}}
          {{if eq .Page "audit"}}<h1 class="page-title">Audit & Evidence</h1>{{end}}
          {{if eq .Page "tickets"}}<h1 class="page-title">Tickets</h1>{{end}}
          {{if eq .Page "evaluations"}}<h1 class="page-title">Evaluations</h1>{{end}}
          <div class="page-sub">{{.Report.Summary}}</div>
        </div>
        <form method="GET" action="/" class="search-bar">
          <input name="q" placeholder="Search ID / signer / summary" value="{{.Query}}" />
          <button type="submit">Search</button>
          <button class="secondary" type="button" onclick="window.location='/'">Reset</button>
        </form>
      </header>
      <main>
    {{if eq .Page "overview"}}
    <section class="grid">
      <div class="card kpi">
        <div class="label">Rules Evaluated</div>
        <div class="value">{{.StatsTotal}}</div>
        <div class="trend">Feasible: {{.StatsFeasible}} · Infeasible: {{.StatsInfeasible}}</div>
      </div>
      <div class="card kpi">
        <div class="label">Evidence Gaps</div>
        <div class="value">{{.StatsGaps}}</div>
        <div class="trend">Missing preconditions & evidence</div>
      </div>
      <div class="card kpi">
        <div class="label">Confidence</div>
        <div class="value">{{printf "%.2f" .AvgConfidence}}</div>
        <div class="trend">Decay window: {{.DecayWindow}}</div>
        {{if .Report.Reasoning.ConfidenceModel}}
          <div class="trend">Model: {{.Report.Reasoning.ConfidenceModel}}</div>
        {{end}}
        <div class="meter"><span style="width: {{.ConfidencePct}}%"></span></div>
      </div>
      <div class="card kpi">
        <div class="label">Verdict</div>
        <div class="value">{{.Verdict}}</div>
        <div class="trend">Human authority required for escalation</div>
      </div>
    </section>

    <section class="card">
      <div class="section-title">Drift Signals</div>
      <ul class="list">
        {{if .Report.DriftSignals}}
          {{range .Report.DriftSignals}}
            <li>{{.}}</li>
          {{end}}
        {{else}}
          <li class="muted">No drift signals detected.</li>
        {{end}}
      </ul>
    </section>

    <section class="card">
      <div class="section-title">Suggested Actions <span class="pill">Human approval required</span></div>
      {{if .Suggestions}}
        <div class="rule-grid">
          {{range .Suggestions}}
            <div class="rule-card">
              <div style="display:flex; justify-content:space-between; align-items:center; gap:8px; flex-wrap:wrap;">
                <div>
                  <strong>{{.RuleID}}</strong> — {{.Name}}
                  <div class="muted">{{.Explanation}}</div>
                </div>
                <span class="status feasible">SUGGEST</span>
              </div>
              <div class="footer-note">Confidence: {{printf "%.2f" .Confidence}} · Score: {{printf "%.2f" .Score}}</div>
              {{if .EvidenceIDs}}
                <details>
                  <summary>Evidence</summary>
                  <div class="muted">Event IDs: {{range .EvidenceIDs}}{{.}} {{end}}</div>
                </details>
              {{end}}
            </div>
          {{end}}
        </div>
      {{else}}
        <p class="muted">No suggestions. Guardrails active (low confidence or evidence gaps).</p>
      {{end}}
    </section>

    <section class="card">
      <div class="section-title">Top Evidence Gaps</div>
      <ul class="list">
        {{if .TopGaps}}
          {{range .TopGaps}}
            <li><span class="status incomplete">{{.Type}}</span> — {{.Count}} occurrences</li>
          {{end}}
        {{else}}
          <li class="muted">No missing evidence categories.</li>
        {{end}}
      </ul>
    </section>

    <section class="card">
      <div class="section-title">Recent Audit Artifacts</div>
      <table>
        <tr><th>ID</th><th>Created</th><th>Summary</th><th>Findings</th></tr>
        {{range .Artifacts}}
          <tr>
            <td>{{.ID}}</td>
            <td>{{.CreatedAt}}</td>
            <td>{{.Summary}}</td>
            <td>{{len .Findings}}</td>
          </tr>
        {{end}}
      </table>
    </section>
    {{end}}

    {{if eq .Page "attack-graph"}}
    <section class="card">
      <div class="section-title">Attack Graph <span class="pill">Progression</span></div>
      <div class="graph-canvas">
        {{if .GraphSVG}}
          {{.GraphSVG}}
        {{else}}
          {{if or .Report.State.GraphOverlay.CurrentNodes .Report.State.GraphOverlay.Reachable}}
            {{range .Report.State.GraphOverlay.CurrentNodes}}
              <div class="node current">{{.}}</div>
            {{end}}
            {{range .Report.State.GraphOverlay.Reachable}}
              <div class="node reachable">{{.}}</div>
            {{end}}
          {{else}}
            <div class="muted">No active graph nodes for the selected window.</div>
          {{end}}
        {{end}}
      </div>
      <div class="section-grid">
        <div>
          <div class="muted">Current Nodes</div>
          <ul class="list">
            {{if .Report.State.GraphOverlay.CurrentNodes}}
              {{range .Report.State.GraphOverlay.CurrentNodes}}
                <li>{{.}}</li>
              {{end}}
            {{else}}
              <li class="muted">No active nodes detected</li>
            {{end}}
          </ul>
        </div>
        <div>
          <div class="muted">Reachable Nodes</div>
          <ul class="list">
            {{if .Report.State.GraphOverlay.Reachable}}
              {{range .Report.State.GraphOverlay.Reachable}}
                <li>{{.}}</li>
              {{end}}
            {{else}}
              <li class="muted">No reachable expansion recorded</li>
            {{end}}
          </ul>
        </div>
      </div>
      <div class="footer-note">Graph overlay shows current attacker position and reachable state transitions.</div>
    </section>
    <section class="card">
      <div class="section-title">Progression Timeline</div>
      <div class="timeline">
        {{if .Report.State.Progression}}
          {{range .Report.State.Progression}}
            <div class="timeline-item">
              <div class="time">{{.Time}}</div>
              <div>
                <div><span class="tag">{{.Stage}}</span> — {{.Action}}</div>
                <div class="muted">Asset: {{.Asset}} · Principal: {{.Principal}} · Confidence: {{printf "%.2f" .Confidence}}</div>
                <div class="muted">{{.Rationale}}</div>
              </div>
            </div>
          {{end}}
        {{else}}
          <p class="muted">No progression events recorded.</p>
        {{end}}
      </div>
    </section>
    {{end}}

    {{if eq .Page "reasoning"}}
    <section class="card">
      <div class="section-title">Reasoning Panel <span class="pill">Explainability</span></div>
      <div class="section-grid">
        <div>
          <div class="muted">Verdict</div>
          <div class="status {{.Verdict}}">{{.Verdict}}</div>
          <div class="footer-note">Causal feasibility + evidence completeness</div>
          {{if .Report.Reasoning.ConfidenceNote}}
            <div class="footer-note">{{.Report.Reasoning.ConfidenceNote}}</div>
          {{end}}
        </div>
        <div>
          <div class="muted">Next Attacker Actions</div>
          <ul class="list">
            {{if .Report.NextMoves}}
              {{range .Report.NextMoves}}
                <li>{{.}}</li>
              {{end}}
            {{else}}
              <li class="muted">No projected moves at this time</li>
            {{end}}
          </ul>
        </div>
        <div>
          <div class="muted">Evidence Gaps</div>
          <ul class="list">
            {{if .Report.Findings}}
              {{range .Report.Findings}}
                <li>{{.}}</li>
              {{end}}
            {{else}}
              <li class="muted">No evidence gaps recorded</li>
            {{end}}
          </ul>
        </div>
      </div>
      <div class="section-title" style="margin-top:14px;">Causal Explanation</div>
      {{if .Report.Reasoning.Narrative}}
        <ol>
          {{range .Report.Reasoning.Narrative}}
            <li>{{.}}</li>
          {{end}}
        </ol>
      {{else}}
        <p class="muted">No narrative chain generated for this run.</p>
      {{end}}
    </section>
    <section class="card">
      <div class="section-title">Suggested Actions <span class="pill">Human approval required</span></div>
      {{if .Suggestions}}
        <div class="rule-grid">
          {{range .Suggestions}}
            <div class="rule-card">
              <div style="display:flex; justify-content:space-between; align-items:center; gap:8px; flex-wrap:wrap;">
                <div>
                  <strong>{{.RuleID}}</strong> — {{.Name}}
                  <div class="muted">{{.Explanation}}</div>
                </div>
                <span class="status feasible">SUGGEST</span>
              </div>
              <div class="footer-note">Confidence: {{printf "%.2f" .Confidence}} · Score: {{printf "%.2f" .Score}}</div>
              {{if .EvidenceIDs}}
                <details>
                  <summary>Evidence</summary>
                  <div class="muted">Event IDs: {{range .EvidenceIDs}}{{.}} {{end}}</div>
                </details>
              {{end}}
            </div>
          {{end}}
        </div>
      {{else}}
        <p class="muted">No suggestions. Guardrails active (low confidence or evidence gaps).</p>
      {{end}}
    </section>
    <section class="card">
      <div class="section-title">Evidence Used / Missing</div>
      <div class="rule-grid">
        {{range .RuleViews}}
          <div class="rule-card">
            <div style="display:flex; justify-content:space-between; align-items:center; gap:8px; flex-wrap:wrap;">
              <div>
                <strong>{{.Rule.RuleID}}</strong> — {{.Rule.Name}}
                <div class="muted">{{.Rule.Explanation}}</div>
              </div>
              <span class="status {{.Status}}">{{.Status}}</span>
            </div>
            <div class="chip-row">
              {{if .Rule.DecisionLabel}}
                <span class="status label-{{.Rule.DecisionLabel}}">{{.Rule.DecisionLabel}}</span>
              {{end}}
              {{if .Rule.ReasonCode}}
                <span class="pill">{{.Rule.ReasonCode}}</span>
              {{end}}
              {{if .Rule.ThreadID}}
                <span class="pill">Thread {{.Rule.ThreadID}}</span>
              {{else if .Rule.ThreadReason}}
                <span class="pill">Thread: {{.Rule.ThreadReason}}</span>
              {{end}}
              {{if gt .Rule.ThreadConfidence 0.0}}
                <span class="pill">Thread confidence {{printf "%.2f" .Rule.ThreadConfidence}}</span>
              {{end}}
              {{if .Rule.CacheHit}}
                <span class="pill">Cache HIT</span>
              {{end}}
            </div>
            {{if .HasEvents}}
              <details>
                <summary>Evidence Used</summary>
                <div class="muted">Event IDs: {{range .Rule.SupportingEventIDs}}{{.}} {{end}}</div>
              </details>
            {{end}}
            {{if .HasGaps}}
              <details>
                <summary>Evidence Missing ({{.GapCount}})</summary>
                <ul>
                  {{range .Rule.MissingEvidence}}
                    <li>{{.Type}} — {{.Description}}</li>
                  {{end}}
                </ul>
              </details>
            {{end}}
          </div>
        {{end}}
      </div>
    </section>
    {{end}}

    {{if eq .Page "queue"}}
    <section>
      <div class="section-title">Reasoning Queue</div>
      <div class="rule-grid">
        {{range .RuleViews}}
          <div class="rule-card">
            <div style="display:flex; justify-content:space-between; align-items:center; gap:8px; flex-wrap:wrap;">
              <div>
                <strong>{{.Rule.RuleID}}</strong> — {{.Rule.Name}}
                <div class="muted">{{.Rule.Explanation}}</div>
              </div>
              <span class="status {{.Status}}">{{.Status}}</span>
            </div>
            <div class="chip-row">
              {{if .Rule.DecisionLabel}}
                <span class="status label-{{.Rule.DecisionLabel}}">{{.Rule.DecisionLabel}}</span>
              {{end}}
              {{if .Rule.ReasonCode}}
                <span class="pill">{{.Rule.ReasonCode}}</span>
              {{end}}
              {{if .Rule.ThreadID}}
                <span class="pill">Thread {{.Rule.ThreadID}}</span>
              {{else if .Rule.ThreadReason}}
                <span class="pill">Thread: {{.Rule.ThreadReason}}</span>
              {{end}}
              {{if gt .Rule.ThreadConfidence 0.0}}
                <span class="pill">Thread confidence {{printf "%.2f" .Rule.ThreadConfidence}}</span>
              {{end}}
              {{if .Rule.CacheHit}}
                <span class="pill">Cache HIT</span>
              {{end}}
            </div>
            <div class="footer-note">Confidence: {{printf "%.2f" .Rule.Confidence}}</div>
            {{if .HasEvents}}
              <details>
                <summary>Evidence Used</summary>
                <div class="muted">Event IDs: {{range .Rule.SupportingEventIDs}}{{.}} {{end}}</div>
              </details>
            {{end}}
            {{if .HasGaps}}
              <details>
                <summary>Evidence Missing ({{.GapCount}})</summary>
                <ul>
                  {{range .Rule.MissingEvidence}}
                    <li>{{.Type}} — {{.Description}}</li>
                  {{end}}
                </ul>
              </details>
            {{end}}
          </div>
        {{end}}
      </div>
    </section>
    {{if ne .Role "auditor"}}
      <section class="card">
        <div class="section-title">Log Analyst Disagreement</div>
        <form method="POST" action="/disagree" class="approval-form">
          <input name="analyst_id" placeholder="analyst id" required />
          <input name="rule_id" placeholder="rule id" required />
          <input name="expected" placeholder="expected verdict" />
          <input name="actual" placeholder="actual verdict" />
          <input name="rationale" class="full" placeholder="rationale" />
          <button type="submit">Log Disagreement</button>
        </form>
        <div class="footer-note">Disagreements are captured as signed reasoning constraints for governance review.</div>
      </section>
    {{else}}
      <p class="muted">Auditor role is read-only.</p>
    {{end}}
    {{end}}

    {{if eq .Page "governance"}}
    <section>
      <div class="section-title">Governance & Compliance</div>
      <div class="section-grid">
        <div class="card">
          <div class="section-title">Signed Approvals <span class="pill">Human Authority</span></div>
          <ul class="list">
            {{if .Approvals}}
              {{range .Approvals}}
                <li>
                  <strong>{{.Approval.ID}}</strong>
                  {{if ge (index $.ApprovalsByID .Approval.ID) 2}}<span class="status govern">DUAL</span>{{end}}
                  — {{.Approval.SignerID}} ({{.Approval.SignerRole}})<br/>
                  <span class="muted">Expires: {{.Approval.ExpiresAt}} · Gaps: {{range .EvidenceGaps}}{{.}} {{end}}</span>
                </li>
              {{end}}
            {{else}}
              <li class="muted">No approvals recorded.</li>
            {{end}}
          </ul>
          <div class="footer-note">Dual-approval required for critical trust changes. No auto-remediation.</div>
        </div>
        <div class="card">
          <div class="section-title">Approval Summary</div>
          <ul class="list">
            <li>Total approvals: {{len .Approvals}}</li>
            <li>Dual-approval IDs: {{.DualCount}}</li>
          </ul>
          <div class="footer-note">Dual approvals are flagged when two or more signatures share the same ID.</div>
        </div>
        <div class="card">
          <div class="section-title">Signed Artifacts</div>
          <ul class="list">
            {{if .Signed}}
              {{range .Signed}}
                <li>{{.ID}} — {{.Signer}} <span class="status {{.Status}}">{{.Status}}</span></li>
              {{end}}
            {{else}}
              <li class="muted">No signed artifacts available.</li>
            {{end}}
          </ul>
          <div class="link-row">
            <a href="/download?type=audit">Download Audit Log</a>
            {{if .SignedAuditPath}}<a href="/download?type=signed">Download Signed Audit</a>{{end}}
            <a href="/download?type=approvals">Download Approvals Log</a>
          </div>
        </div>
      </div>
      {{if or (eq .Role "approver") (eq .Role "admin")}}
        <section class="card" style="margin-top:12px;">
          <div class="section-title">Generate Approval</div>
          <form method="POST" action="/approve" class="approval-form">
            <input name="id" placeholder="approval id" required />
            <input name="signer" placeholder="signer" required />
            <input name="role" placeholder="role" value="approver" />
            <input name="ttl" placeholder="10m" />
            <input name="gaps" class="full" placeholder="evidence gaps (comma separated)" />
            <input name="rationale" class="full" placeholder="approval rationale" />
            <button type="submit">Approve</button>
          </form>
          <div class="footer-note">Approvals are cryptographically signed and auditable.</div>
        </section>
      {{else}}
        <p class="muted">Approvals require approver/admin role.</p>
      {{end}}
    </section>
    <section class="card">
      <div class="section-title">Suggested Actions <span class="pill">Human approval required</span></div>
      {{if .Suggestions}}
        <div class="rule-grid">
          {{range .Suggestions}}
            <div class="rule-card">
              <div style="display:flex; justify-content:space-between; align-items:center; gap:8px; flex-wrap:wrap;">
                <div>
                  <strong>{{.RuleID}}</strong> — {{.Name}}
                  <div class="muted">{{.Explanation}}</div>
                </div>
                <span class="status feasible">SUGGEST</span>
              </div>
              <div class="footer-note">Confidence: {{printf "%.2f" .Confidence}} · Score: {{printf "%.2f" .Score}}</div>
              {{if .EvidenceIDs}}
                <details>
                  <summary>Evidence</summary>
                  <div class="muted">Event IDs: {{range .EvidenceIDs}}{{.}} {{end}}</div>
                </details>
              {{end}}
            </div>
          {{end}}
        </div>
      {{else}}
        <p class="muted">No suggestions. Guardrails active (low confidence or evidence gaps).</p>
      {{end}}
    </section>
    {{end}}

    {{if eq .Page "audit"}}
    <section class="card">
      <div class="section-title">Audit Artifacts</div>
      <table>
        <tr><th>ID</th><th>Created</th><th>Summary</th><th>Findings</th></tr>
        {{range .Artifacts}}
          <tr>
            <td>{{.ID}}</td>
            <td>{{.CreatedAt}}</td>
            <td>{{.Summary}}</td>
            <td>{{len .Findings}}</td>
          </tr>
        {{end}}
      </table>
      <div class="link-row">
        <a href="/download?type=audit">Download Audit Log</a>
        {{if .SignedAuditPath}}<a href="/download?type=signed">Download Signed Audit</a>{{end}}
      </div>
    </section>
    <section>
      <div class="section-title">Audit & Evidence</div>
      <div class="timeline">
        {{range .Artifacts}}
          <div class="timeline-item">
            <div class="time">{{.CreatedAt}}</div>
            <div>
              <div><span class="tag">{{.ID}}</span></div>
              <div class="muted">{{.Summary}}</div>
              <details>
                <summary>Replay Details</summary>
                <div class="muted">Hash: {{.Hash}}</div>
                <div class="muted">Prev Hash: {{.PrevHash}}</div>
                {{if .Reasoning}}
                  <div class="muted">Reasoning Chain:</div>
                  <ul>
                    {{range .Reasoning}}
                      <li>{{.}}</li>
                    {{end}}
                  </ul>
                {{end}}
              </details>
            </div>
          </div>
        {{end}}
      </div>
    </section>
    {{end}}

    {{if eq .Page "tickets"}}
    <section class="card">
      <div class="section-title">Tickets</div>
      <table>
        <tr><th>ID</th><th>Status</th><th>Label</th><th>Reason</th><th>Thread</th><th>Host</th><th>Principal</th><th>Updated</th></tr>
        {{if .Report.State.Tickets}}
          {{range .Report.State.Tickets}}
            <tr>
              <td><a href="/tickets?ticket={{.ID}}">{{.ID}}</a></td>
              <td>{{.Status}}</td>
              <td>{{.DecisionLabel}}</td>
              <td>{{.ReasonCode}}</td>
              <td>{{.ThreadID}}</td>
              <td>{{.Host}}</td>
              <td>{{.Principal}}</td>
              <td>{{.UpdatedAt}}</td>
            </tr>
          {{end}}
        {{else}}
          <tr><td colspan="8" class="muted">No tickets yet.</td></tr>
        {{end}}
      </table>
      <div class="footer-note">Tickets are created per thread (host + principal + 2h window).</div>
    </section>

    {{if .SelectedTicket.ID}}
    <section class="card">
      <div class="section-title">Ticket Detail</div>
      <div class="section-grid">
        <div>
          <div class="muted">Ticket</div>
          <div><strong>{{.SelectedTicket.ID}}</strong></div>
          <div class="footer-note">Status: {{.SelectedTicket.Status}}</div>
          <div class="footer-note">Label: {{.SelectedTicket.DecisionLabel}}</div>
          <div class="footer-note">Reason: {{.SelectedTicket.ReasonCode}}</div>
          <div class="footer-note">Thread: {{.SelectedTicket.ThreadID}}</div>
          <div class="footer-note">Updated: {{.SelectedTicket.UpdatedAt}}</div>
          <div class="link-row">
            <a href="/download?type=ticket&id={{.SelectedTicket.ID}}">Download Ticket Export</a>
          </div>
        </div>
        <div>
          <div class="muted">Rules</div>
          <ul class="list">
            {{range .SelectedTicket.RuleIDs}}
              <li>{{.}}</li>
            {{end}}
          </ul>
        </div>
      </div>
      <div class="section-title" style="margin-top:14px;">Evidence & Decisions</div>
      <div class="rule-grid">
        {{range .TicketResults}}
          <div class="rule-card">
            <div style="display:flex; justify-content:space-between; align-items:center; gap:8px; flex-wrap:wrap;">
              <div>
                <strong>{{.RuleID}}</strong> — {{.Name}}
                <div class="muted">{{.Explanation}}</div>
              </div>
              <span class="status {{if .Feasible}}feasible{{else if .MissingEvidence}}incomplete{{else}}impossible{{end}}">{{if .Feasible}}feasible{{else if .MissingEvidence}}incomplete{{else}}impossible{{end}}</span>
            </div>
            <div class="chip-row">
              {{if .DecisionLabel}}
                <span class="status label-{{.DecisionLabel}}">{{.DecisionLabel}}</span>
              {{end}}
              {{if .ReasonCode}}
                <span class="pill">{{.ReasonCode}}</span>
              {{end}}
              {{if .ThreadID}}
                <span class="pill">Thread {{.ThreadID}}</span>
              {{else if .ThreadReason}}
                <span class="pill">Thread: {{.ThreadReason}}</span>
              {{end}}
              {{if gt .ThreadConfidence 0.0}}
                <span class="pill">Thread confidence {{printf "%.2f" .ThreadConfidence}}</span>
              {{end}}
            </div>
            {{if .SupportingEventIDs}}
              <details>
                <summary>Evidence IDs</summary>
                <div class="muted">{{range .SupportingEventIDs}}{{.}} {{end}}</div>
              </details>
            {{end}}
            {{if .MissingEvidence}}
              <details>
                <summary>Missing Evidence</summary>
                <ul>
                  {{range .MissingEvidence}}
                    <li>{{.Type}} — {{.Description}}</li>
                  {{end}}
                </ul>
              </details>
            {{end}}
          </div>
        {{end}}
      </div>
      <div class="section-title" style="margin-top:14px;">Approvals</div>
      {{if .TicketApprovals}}
        <table>
          <tr><th>ID</th><th>Signer</th><th>Role</th><th>Expires</th><th>Rationale</th></tr>
          {{range .TicketApprovals}}
            <tr>
              <td>{{.Approval.ID}}</td>
              <td>{{.Approval.SignerID}}</td>
              <td>{{.Approval.Role}}</td>
              <td>{{.Approval.ExpiresAt}}</td>
              <td>{{.Rationale}}</td>
            </tr>
          {{end}}
        </table>
      {{else}}
        <p class="muted">No approvals attached to this ticket.</p>
      {{end}}
    </section>
    {{end}}
    {{end}}

    {{if eq .Page "evaluations"}}
    <section class="card">
      <div class="section-title">Evaluations</div>
      <div class="section-grid">
        <div>
          <div class="muted">Baseline Accuracy</div>
          <div class="value">{{printf "%.2f" .AvgConfidence}}</div>
          <div class="footer-note">Latest evaluation run (synthetic + realistic).</div>
        </div>
        <div>
          <div class="muted">Drift Signals</div>
          <ul class="list">
            {{if .Report.DriftSignals}}
              {{range .Report.DriftSignals}}
                <li>{{.}}</li>
              {{end}}
            {{else}}
              <li class="muted">No drift signals detected.</li>
            {{end}}
          </ul>
        </div>
      </div>
    </section>
    {{end}}
      </main>
    </div>
  </div>
</body>
</html>`

package ui

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"aegisr/internal/approval"
	"aegisr/internal/audit"
	"aegisr/internal/governance"
	"aegisr/internal/model"
	"aegisr/internal/ops"
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

type keypair struct {
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
}

func NewServer(auditPath string, approvalsPath string, signedAuditPath string, reportPath string, profilesPath string, disagreementsPath string, keypairPath string, basicUser string, basicPass string) (*Server, error) {
	kp := keypair{}
	if keypairPath != "" {
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
	mux.HandleFunc("/", s.auth(s.index))
	mux.HandleFunc("/approve", s.auth(s.approve))
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

func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	artifacts, _ := loadArtifacts(s.AuditPath)
	signed, _ := loadSignedArtifacts(s.SignedAuditPath)
	report, _ := loadReasoningReport(s.ReportPath)
	s.Mu.Lock()
	approvals := make([]ApprovalRecord, len(s.Approvals))
	copy(approvals, s.Approvals)
	profiles := make([]governance.AnalystProfile, len(s.Profiles))
	copy(profiles, s.Profiles)
	disagreements := make([]governance.Disagreement, len(s.Disagreements))
	copy(disagreements, s.Disagreements)
	s.Mu.Unlock()
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if q != "" {
		artifacts = filterArtifacts(artifacts, q)
		approvals = filterApprovals(approvals, q)
		signed = filterSigned(signed, q)
	}
	tmpl := template.Must(template.New("index").Parse(indexHTML))
	_ = tmpl.Execute(w, struct {
		Artifacts       []audit.Artifact
		Approvals       []ApprovalRecord
		Signed          []SignedStatus
		Report          model.ReasoningReport
		Profiles        []governance.AnalystProfile
		Disagreements   []governance.Disagreement
		Role            string
		AuditPath       string
		SignedAuditPath string
		Query           string
	}{Artifacts: artifacts, Approvals: approvals, Signed: signed, Report: report, Profiles: profiles, Disagreements: disagreements, Role: s.currentRole(r), AuditPath: s.AuditPath, SignedAuditPath: s.SignedAuditPath, Query: q})
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

const indexHTML = `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Aegis-R Review</title>
  <style>
    body { font-family: Georgia, serif; margin: 24px; }
    table { border-collapse: collapse; width: 100%; }
    th, td { border-bottom: 1px solid #ddd; padding: 8px; text-align: left; }
    .muted { color: #666; font-size: 0.9em; }
    form { margin-top: 16px; }
    input { padding: 6px; margin-right: 8px; }
  </style>
</head>
<body>
  <h1>Aegis-R Analyst Review</h1>
  <p class="muted">Recent audit artifacts</p>
  <form method="GET" action="/">
    <input name="q" placeholder="search id/signer/summary" value="{{.Query}}" />
    <button type="submit">Search</button>
  </form>
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
  <h2>Audit Timeline</h2>
  <ul>
    {{range .Artifacts}}
      <li>{{.CreatedAt}} — {{.ID}} — {{.Summary}}</li>
    {{end}}
  </ul>
  {{if .Signed}}
  <h2>Signed Artifacts</h2>
  <table>
    <tr><th>ID</th><th>Signer</th><th>Status</th></tr>
    {{range .Signed}}
      <tr>
        <td>{{.ID}}</td>
        <td>{{.Signer}}</td>
        <td>{{.Status}}</td>
      </tr>
    {{end}}
  </table>
  {{end}}
  {{if .Report.Results}}
  <h2>Per-Rule Evidence</h2>
  <table>
    <tr><th>Rule</th><th>Feasible</th><th>Evidence IDs</th><th>Missing</th></tr>
    {{range .Report.Results}}
      <tr>
        <td>{{.RuleID}}</td>
        <td>{{.Feasible}}</td>
        <td>{{range .SupportingEventIDs}}{{.}} {{end}}</td>
        <td>{{range .MissingEvidence}}{{.Type}} {{end}}</td>
      </tr>
    {{end}}
  </table>
  {{end}}
  {{if .Profiles}}
  <h2>Analyst Profiles</h2>
  <table>
    <tr><th>ID</th><th>Name</th><th>Specialties</th><th>Notes</th></tr>
    {{range .Profiles}}
      <tr>
        <td>{{.ID}}</td>
        <td>{{.Name}}</td>
        <td>{{range .Specialties}}{{.}} {{end}}</td>
        <td>{{.Notes}}</td>
      </tr>
    {{end}}
  </table>
  {{end}}
  {{if .Disagreements}}
  <h2>Disagreement Feedback</h2>
  <table>
    <tr><th>At</th><th>Analyst</th><th>Rule</th><th>Expected</th><th>Actual</th><th>Rationale</th></tr>
    {{range .Disagreements}}
      <tr>
        <td>{{.At}}</td>
        <td>{{.AnalystID}}</td>
        <td>{{.RuleID}}</td>
        <td>{{.Expected}}</td>
        <td>{{.Actual}}</td>
        <td>{{.Rationale}}</td>
      </tr>
    {{end}}
  </table>
  {{end}}
  <div style="margin-top:12px;">
    <a href="/download?type=audit">Download Audit Log</a>
    {{if .SignedAuditPath}} | <a href="/download?type=signed">Download Signed Audit</a>{{end}}
  </div>
  <h2>Approval History</h2>
  <table>
    <tr><th>ID</th><th>Signer</th><th>Role</th><th>Expires</th><th>Rationale</th><th>Gaps</th><th>Download</th></tr>
    {{range .Approvals}}
      <tr>
        <td>{{.Approval.ID}}</td>
        <td>{{.Approval.SignerID}}</td>
        <td>{{.Approval.SignerRole}}</td>
        <td>{{.Approval.ExpiresAt}}</td>
        <td>{{.Rationale}}</td>
        <td>{{range .EvidenceGaps}}{{.}} {{end}}</td>
        <td><a href="/download?id={{.Approval.ID}}">Download</a></td>
      </tr>
    {{end}}
  </table>
  {{if or (eq .Role "approver") (eq .Role "admin")}}
    <h2>Generate Approval</h2>
    <form method="POST" action="/approve">
      <input name="id" placeholder="approval id" required />
      <input name="signer" placeholder="signer" required />
      <input name="role" placeholder="role" value="approver" />
      <input name="ttl" placeholder="10m" />
      <input name="gaps" placeholder="evidence gaps (comma separated)" />
      <input name="rationale" placeholder="approval rationale" />
      <button type="submit">Approve</button>
    </form>
  {{else}}
    <p class="muted">Approvals require approver/admin role.</p>
  {{end}}
</body>
</html>`

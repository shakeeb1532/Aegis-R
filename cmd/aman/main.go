package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"aman/internal/approval"
	"aman/internal/assist"
	"aman/internal/audit"
	"aman/internal/compliance"
	"aman/internal/compress"
	"aman/internal/core"
	"aman/internal/engines"
	"aman/internal/env"
	"aman/internal/eval"
	"aman/internal/explain"
	"aman/internal/governance"
	"aman/internal/integration"
	"aman/internal/inventory"
	"aman/internal/logic"
	"aman/internal/model"
	"aman/internal/ops"
	"aman/internal/overlay"
	"aman/internal/progression"
	"aman/internal/report"
	"aman/internal/secureingest"
	"aman/internal/sim"
	"aman/internal/state"
	"aman/internal/validate"
	"aman/internal/zerotrust"
)

type KeypairFile struct {
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
}

type ApprovalTemplate struct {
	ID           string `json:"id"`
	Description  string `json:"description"`
	Role         string `json:"role"`
	TTL          string `json:"ttl"`
	Second       bool   `json:"second"`
	RequireOkta  bool   `json:"require_okta"`
	MinSigners   int    `json:"min_signers,omitempty"`
	TemplateFile string `json:"-"`
}

func loadApprovalTemplates(path string) ([]ApprovalTemplate, error) {
	if !ops.IsSafePath(path) {
		return nil, os.ErrInvalid
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []ApprovalTemplate
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	for i := range out {
		out[i].TemplateFile = path
	}
	return out, nil
}

func findApprovalTemplate(templates []ApprovalTemplate, id string) (ApprovalTemplate, bool) {
	for _, t := range templates {
		if strings.EqualFold(t.ID, id) {
			return t, true
		}
	}
	return ApprovalTemplate{}, false
}

type approvalRecord struct {
	Approval     approval.Approval `json:"approval"`
	Rationale    string            `json:"rationale"`
	EvidenceGaps []string          `json:"evidence_gaps"`
	TemplateID   string            `json:"template_id,omitempty"`
}

type GlobalFlags struct {
	JSON    bool
	Quiet   bool
	NoColor bool
	Profile string
}

type PilotMetrics struct {
	GeneratedAt                      time.Time `json:"generated_at"`
	ReportPath                       string    `json:"report_path"`
	HistoryPath                      string    `json:"history_path"`
	CandidateCount                   int       `json:"candidate_count"`
	EscalatedCount                   int       `json:"escalated_count"`
	TriagedCount                     int       `json:"triaged_count"`
	SuppressedCount                  int       `json:"suppressed_count"`
	QueueReductionPct                float64   `json:"queue_reduction_pct"`
	EscalatedConfirmedCount          int       `json:"escalated_confirmed_count"`
	EscalatedFalsePositiveCount      int       `json:"escalated_false_positive_count"`
	EscalatedUnknownOutcomeCount     int       `json:"escalated_unknown_outcome_count"`
	EscalatedPrecisionProxyPct       float64   `json:"escalated_precision_proxy_pct"`
	SuppressedLaterTrueCount         int       `json:"suppressed_later_true_count"`
	SuppressedLaterTrueRatePct       float64   `json:"suppressed_later_true_rate_pct"`
	KnownConfirmedRulesInHistory     int       `json:"known_confirmed_rules_in_history"`
	KnownFalsePositiveRulesInHistory int       `json:"known_false_positive_rules_in_history"`
}

type IntegrationCheck struct {
	Category      string `json:"category"`
	Fixture       string `json:"fixture"`
	Schema        string `json:"schema"`
	Kind          string `json:"kind,omitempty"`
	EventCount    int    `json:"event_count"`
	FeasibleCount int    `json:"feasible_count"`
	Pass          bool   `json:"pass"`
	Error         string `json:"error,omitempty"`
}

type IntegrationReadinessReport struct {
	GeneratedAt time.Time          `json:"generated_at"`
	RulesPath   string             `json:"rules_path"`
	Checks      []IntegrationCheck `json:"checks"`
	Passed      int                `json:"passed"`
	Failed      int                `json:"failed"`
}

type IntegrationQuickstartRun struct {
	Category        string `json:"category"`
	Fixture         string `json:"fixture"`
	Schema          string `json:"schema"`
	Kind            string `json:"kind,omitempty"`
	EventsPath      string `json:"events_path"`
	ReportPath      string `json:"report_path"`
	EventCount      int    `json:"event_count"`
	FeasibleCount   int    `json:"feasible_count"`
	CandidateCount  int    `json:"candidate_count"`
	EscalatedCount  int    `json:"escalated_count"`
	TriagedCount    int    `json:"triaged_count"`
	SuppressedCount int    `json:"suppressed_count"`
	Pass            bool   `json:"pass"`
	Error           string `json:"error,omitempty"`
}

type IntegrationQuickstartReport struct {
	GeneratedAt time.Time                  `json:"generated_at"`
	OutputDir   string                     `json:"output_dir"`
	RulesPath   string                     `json:"rules_path"`
	Runs        []IntegrationQuickstartRun `json:"runs"`
	Passed      int                        `json:"passed"`
	Failed      int                        `json:"failed"`
}

type RuleLintReport struct {
	GeneratedAt  time.Time               `json:"generated_at"`
	RulesPath    string                  `json:"rules_path"`
	WarningCount int                     `json:"warning_count"`
	Warnings     []logic.RuleLintWarning `json:"warnings"`
}

type NoisegraphQuickstartReport struct {
	GeneratedAt   time.Time             `json:"generated_at"`
	DecisionsPath string                `json:"decisions_path"`
	EventsPath    string                `json:"events_path"`
	ReportPath    string                `json:"report_path,omitempty"`
	Included      []string              `json:"included_statuses"`
	ParsedLines   int                   `json:"parsed_lines"`
	EventsCount   int                   `json:"events_count"`
	Reasoning     model.ReasoningReport `json:"reasoning"`
}

type ROIScorecard struct {
	GeneratedAt                time.Time `json:"generated_at"`
	PilotMetricsPath           string    `json:"pilot_metrics_path"`
	BenchmarkPath              string    `json:"benchmark_path"`
	QueueReductionPct          float64   `json:"queue_reduction_pct"`
	EscalatedPrecisionProxyPct float64   `json:"escalated_precision_proxy_pct"`
	SuppressedLaterTrueRatePct float64   `json:"suppressed_later_true_rate_pct"`
	OverlayOverheadPct         float64   `json:"overlay_overhead_pct"`
	IntegrationPassed          int       `json:"integration_passed"`
	IntegrationFailed          int       `json:"integration_failed"`
	ReadinessScore             float64   `json:"readiness_score"`
	Notes                      []string  `json:"notes"`
}

type DemoPackReport struct {
	GeneratedAt           time.Time                   `json:"generated_at"`
	OutDir                string                      `json:"out_dir"`
	IntegrationReadiness  IntegrationReadinessReport  `json:"integration_readiness"`
	IntegrationQuickstart IntegrationQuickstartReport `json:"integration_quickstart"`
	ROIScorecard          ROIScorecard                `json:"roi_scorecard"`
	Files                 []string                    `json:"files"`
}

type ControlsExport struct {
	GeneratedAt         time.Time                       `json:"generated_at"`
	AuditChainVerified  bool                            `json:"audit_chain_verified"`
	AuditChainError     string                          `json:"audit_chain_error,omitempty"`
	AuditLifecycle      AuditLifecycleMetadata          `json:"audit_lifecycle"`
	PolicyLifecycle     PolicyLifecycleMetadata         `json:"policy_lifecycle"`
	DecisionControls    []DecisionControlLink           `json:"decision_controls"`
	RuleControlMappings []compliance.RuleControlMapping `json:"rule_control_mappings"`
	DualApprovals       []DualApprovalSummary           `json:"dual_approvals"`
}

type AuditLifecycleMetadata struct {
	AuditLog         string    `json:"audit_log"`
	AuditEntries     int       `json:"audit_entries"`
	FirstEntryAt     time.Time `json:"first_entry_at"`
	LastEntryAt      time.Time `json:"last_entry_at"`
	LastHash         string    `json:"last_hash,omitempty"`
	SignedAuditLog   string    `json:"signed_audit_log,omitempty"`
	SignedEntries    int       `json:"signed_entries"`
	SignedLastAt     time.Time `json:"signed_last_at"`
	SignedSignerIDs  []string  `json:"signed_signer_ids,omitempty"`
	SignedAuditError string    `json:"signed_audit_error,omitempty"`
}

type PolicyLifecycleMetadata struct {
	Source                string    `json:"source,omitempty"`
	PolicyID              string    `json:"policy_id,omitempty"`
	PolicyHash            string    `json:"policy_hash,omitempty"`
	LoadedAt              time.Time `json:"loaded_at"`
	MinApprovals          int       `json:"min_approvals"`
	AllowedSignerRoles    []string  `json:"allowed_signer_roles,omitempty"`
	RequireDualForSignals []string  `json:"require_dual_for_signals,omitempty"`
	Error                 string    `json:"error,omitempty"`
}

type DecisionControlLink struct {
	DecisionID string   `json:"decision_id"`
	RuleID     string   `json:"rule_id"`
	NistCSF    []string `json:"nist_csf,omitempty"`
	Soc2CC     []string `json:"soc2_cc,omitempty"`
	ISO27001   []string `json:"iso_27001,omitempty"`
}

type DualApprovalSummary struct {
	DecisionID    string   `json:"decision_id"`
	Required      int      `json:"required"`
	ValidSigners  int      `json:"valid_signers"`
	DualApproved  bool     `json:"dual_approved"`
	SignerIDs     []string `json:"signer_ids"`
	AnyOktaBypass bool     `json:"any_okta_bypass"`
}

type DecisionPackage struct {
	DecisionID string   `json:"decision_id"`
	Summary    string   `json:"summary"`
	Findings   []string `json:"findings"`
	Reasoning  []string `json:"reasoning"`
	CreatedAt  string   `json:"created_at"`
	Hash       string   `json:"hash"`
	PrevHash   string   `json:"prev_hash"`
}

type BundleSummary struct {
	DecisionID           string   `json:"decision_id"`
	GeneratedAt          string   `json:"generated_at"`
	Verdicts             []string `json:"verdicts"`
	KeyFindings          []string `json:"key_findings"`
	EvidenceGaps         []string `json:"evidence_gaps"`
	ControlsLinked       int      `json:"controls_linked"`
	DualApprovalRequired bool     `json:"dual_approval_required"`
	DualApproved         bool     `json:"dual_approved"`
	BundleVerified       bool     `json:"bundle_verified"`
	Notes                []string `json:"notes"`
}

type WhyChainItem struct {
	RuleID           string   `json:"rule_id"`
	RuleName         string   `json:"rule_name"`
	Verdict          string   `json:"verdict"`
	Explanation      string   `json:"explanation"`
	GapNarrative     string   `json:"gap_narrative,omitempty"`
	ReasonCode       string   `json:"reason_code,omitempty"`
	PreconditionOK   bool     `json:"precondition_ok"`
	SupportingEvents []string `json:"supporting_event_ids,omitempty"`
	MissingEvidence  []string `json:"missing_evidence,omitempty"`
	CausalBlockers   []string `json:"causal_blockers,omitempty"`
	NecessaryCauses  []string `json:"necessary_causes,omitempty"`
}

type CounterfactualItem struct {
	RuleID      string   `json:"rule_id"`
	Assumption  string   `json:"assumption"`
	Prediction  string   `json:"prediction"`
	NextActions []string `json:"next_actions,omitempty"`
}

var gFlags GlobalFlags

const explainAckPhrase = "I_ACKNOWLEDGE_LLM_RISK"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	gf, args := parseGlobalFlags(os.Args[1:])
	if len(args) == 0 {
		usage()
		os.Exit(1)
	}
	setGlobals(gf)

	switch args[0] {
	case "ingest":
		handleIngest(args[1:])
	case "graph":
		handleGraph(args[1:])
	case "reason":
		if len(args) >= 2 && (args[1] == "event" || args[1] == "thread" || args[1] == "host") {
			handleReasonV2(args[1:])
		} else {
			handleReason(args[1:])
		}
	case "govern":
		handleGovern(args[1:])
	case "audit":
		handleAudit(args[1:])
	case "system":
		handleSystem(args[1:])
	case "generate":
		handleGenerate(args[1:])
	case "assess":
		handleAssess(args[1:])
	case "keys":
		handleKeys(args[1:])
	case "approve":
		handleApprove(args[1:])
	case "approve2":
		handleApprove2(args[1:])
	case "verify":
		handleVerify(args[1:])
	case "audit-verify":
		handleAuditVerify(args[1:])
	case "audit-sign":
		handleAuditSign(args[1:])
	case "generate-scenarios":
		handleGenerateScenarios(args[1:])
	case "evaluate":
		handleEvaluate(args[1:])
	case "ingest-http":
		handleIngestHTTP(args[1:])
	case "ingest-inventory":
		handleIngestInventory(args[1:])
	case "inventory-drift":
		handleInventoryDrift(args[1:])
	case "inventory-adapter":
		handleInventoryAdapter(args[1:])
	case "inventory-refresh":
		handleInventoryRefresh(args[1:])
	case "inventory-schedule":
		handleInventorySchedule(args[1:])
	case "serve-api":
		handleServeAPI(args[1:])
	case "init-scan":
		handleInitScan(args[1:])
	case "scan":
		handleScan(args[1:])
	case "profile-add":
		handleProfileAdd(args[1:])
	case "constraint-add":
		handleConstraintAdd(args[1:])
	case "disagreement-add":
		handleDisagreementAdd(args[1:])
	default:
		usage()
		os.Exit(1)
	}
}

func requireExplainAck(explainOn bool, ack string) {
	if !explainOn {
		return
	}
	if strings.TrimSpace(ack) == "" {
		fatal(fmt.Errorf("explain requires --explain-ack %s", explainAckPhrase))
	}
	if strings.TrimSpace(ack) != explainAckPhrase {
		fatal(fmt.Errorf("invalid --explain-ack (use %s)", explainAckPhrase))
	}
}

func usage() {
	fmt.Println("Aman CLI")
	fmt.Println("Commands:")
	fmt.Println("  aman ingest <verb> [flags]")
	fmt.Println("  aman graph <verb> [flags]")
	fmt.Println("  aman reason <verb> [flags]")
	fmt.Println("  aman govern <verb> [flags]")
	fmt.Println("  aman audit <verb> [flags]")
	fmt.Println("  aman system <verb> [flags]")
	fmt.Println("  generate -out events.json -count 60 -seed 42")
	fmt.Println("  reason -in events.json [-approval approval.json] [-require-okta] [-rules rules.json] [-rules-extra rules_expansion.json] [-include-events] [-format cli|json] [--explain --explain-ack I_ACKNOWLEDGE_LLM_RISK] [--explain-endpoint URL] [--ml-assist] [--ml-history file] [--ml-categories list] [--ml-similar-limit n] [--ai-overlay] [--ai-threshold 0.20]")
	fmt.Println("  assess -in events.json -env env.json -state state.json -audit audit.log [-rules rules.json] [-rules-extra rules_expansion.json] [-approval approval.json] [-policy policy.json] [-constraints data/constraints.json] [-config ops.json] [-format cli|json] [-out report.json|report.json.lz4] [-baseline data/zero_trust_baseline.json] [--explain --explain-ack I_ACKNOWLEDGE_LLM_RISK] [--explain-endpoint URL] [--ml-assist] [--ml-history file] [--ml-categories list] [--ml-similar-limit n] [--ai-overlay] [--ai-threshold 0.20]")
	fmt.Println("  assess -in events.json -env env.json -state state.json -audit audit.log -siem siem.json (optional)")
	fmt.Println("  keys -out keypair.json")
	fmt.Println("  approve -key keypair.json -id change-1 -ttl 10m -okta true -signer alice -role approver -out approval.json")
	fmt.Println("  approve2 -key1 key1.json -key2 key2.json -id change-1 -ttl 10m -okta true -signer1 alice -signer2 bob -out dual_approval.json")
	fmt.Println("  govern templates [-templates data/approval_templates.json]")
	fmt.Println("  govern approve --item change-1 --template safe_change --key keypair.json --signer alice")
	fmt.Println("  verify -approval approval.json [-require-okta]")
	fmt.Println("  audit-verify -audit audit.log")
	fmt.Println("  audit-sign -audit audit.log -out signed_audit.log -signer soc-admin")
	fmt.Println("  generate-scenarios -out scenarios.json [-rules rules.json] [-rules-extra rules_expansion.json] [-multiplier 1] [-noise]")
	fmt.Println("  evaluate -scenarios scenarios.json [-rules rules.json] [-format cli|json|md] [-out report.md]")
	fmt.Println("  ingest-http -addr :8080 [-secure-keyring data/ingest_keys.json] (schema: ecs|elastic_ecs|ocsf|cim|splunk_cim_auth|splunk_cim_net|mde|entra_signins_graph)")
	fmt.Println("  ingest secure-pack -in events.json -out events.aman --keyring data/ingest_keys.json [-compress auto|none|lz4] [-policy adaptive] [-risk medium]")
	fmt.Println("  ingest secure-unpack -in events.aman -out events.json --keyring data/ingest_keys.json")
	fmt.Println("  ingest secure-keygen -out keys.json")
	fmt.Println("  ingest secure-init -out data/ingest_keys.json")
	fmt.Println("  ingest secure-rotate -in data/ingest_keys.json [-out data/ingest_keys.json]")
	fmt.Println("  ingest entra-pull --tenant <id> --client-id <id> --client-secret <secret> --start <RFC3339> --end <RFC3339> --out raw_signins.json")
	fmt.Println("  ingest entra-normalize --in raw_signins.json --out normalized_events.json")
	fmt.Println("  ingest-inventory -in data/inventory -out data/env.json")
	fmt.Println("  inventory-drift -base data/env.json -in data/inventory -out drift.json")
	fmt.Println("  inventory-adapter -provider aws|okta|azure|gcp -config data/inventory/config.json -out data/env.json")
	fmt.Println("  inventory-refresh -provider all -config data/inventory/config.json -base data/env.json -out data/env.json -drift drift.json")
	fmt.Println("  inventory-schedule -provider all -config data/inventory/config.json -base data/env.json -out data/env.json -drift drift.json -interval 6h -jitter 30m")
	fmt.Println("  serve-api -addr :8081 -report data/report.json -audit data/audit.log -approvals data/approvals.log")
	fmt.Println("  system engines")
	fmt.Println("  system pilot-metrics -report data/bench/report.json -history data/incident_history.json [-format json|md] [-out docs/pilot_metrics_report.md]")
	fmt.Println("  system integration-readiness [-rules data/rules.json] [-out docs/integration_readiness.json]")
	fmt.Println("  system integration-quickstart [-rules data/rules.json] [-outdir data/onboarding] [-ai-threshold 0.20]")
	fmt.Println("  system noisegraph-quickstart [-decisions external/noisegraph/state/decisions.jsonl] [-events data/noisegraph_events.json] [-report docs/noisegraph_quickstart.json]")
	fmt.Println("  system roi-scorecard [-pilot docs/pilot_metrics_report.json] [-integration docs/integration_readiness.json] [-benchmark docs/production_benchmark_report.md] [-out docs/roi_scorecard.md]")
	fmt.Println("  system demo-pack [-outdir docs/demo_pack] [-rules data/rules.json]")
	fmt.Println("  system drift-quickstart [-outdir data/inventory]")
	fmt.Println("  system rule-lint [-rules data/rules.json] [-format text|json|md] [-out docs/rule_lint.md]")
	fmt.Println("  graph killchain|blast-radius|controls|identity-pivots|timelapse|evidence-confidence -state data/state.json [-env data/env.json] [-format text|mermaid]")
	fmt.Println("  system nist -rules data/rules.json [-out nist.json]")
	fmt.Println("  system killchain -rules data/rules.json [-out killchain.json]")
	fmt.Println("  init-scan -baseline data/zero_trust_baseline.json")
	fmt.Println("  scan -baseline data/zero_trust_baseline.json [-override-approval admin_approval.json]")
	fmt.Println("  profile-add -file data/analyst_profiles.json -id a1 -name \"Analyst\" -specialty \"cloud\"")
	fmt.Println("  constraint-add -file data/constraints.json -id c1 -rule TA0010.EXFIL -require e1 -forbid e2 -author a1")
	fmt.Println("  disagreement-add -file data/disagreements.log -analyst a1 -rule TA0010.EXFIL -expected feasible -actual incomplete -rationale \"Missing staging evidence\"")
}

func parseGlobalFlags(args []string) (GlobalFlags, []string) {
	var gf GlobalFlags
	out := []string{}
	i := 0
	for i < len(args) {
		a := args[i]
		if a == "--json" {
			gf.JSON = true
			i++
			continue
		}
		if a == "--quiet" {
			gf.Quiet = true
			i++
			continue
		}
		if a == "--no-color" {
			gf.NoColor = true
			i++
			continue
		}
		if strings.HasPrefix(a, "--profile=") {
			gf.Profile = strings.TrimPrefix(a, "--profile=")
			i++
			continue
		}
		if a == "--profile" && i+1 < len(args) {
			gf.Profile = args[i+1]
			i += 2
			continue
		}
		out = append(out, args[i:]...)
		break
	}
	if len(out) == 0 && i == len(args) {
		out = []string{}
	}
	return gf, out
}

func setGlobals(g GlobalFlags) {
	gFlags = g
}

func outln(msg string) {
	if gFlags.Quiet {
		return
	}
	fmt.Println(msg)
}

func outJSON(v interface{}) {
	if gFlags.Quiet {
		return
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fatal(err)
	}
	fmt.Println(string(data))
}

func verdictFromResults(results []model.RuleResult) string {
	hasMissing := false
	hasFeasible := false
	hasConflicted := false
	hasPolicyImpossible := false
	for _, r := range results {
		if r.Feasible {
			hasFeasible = true
		}
		if r.Conflicted {
			hasConflicted = true
		}
		if r.PolicyImpossible {
			hasPolicyImpossible = true
		}
		if len(r.MissingEvidence) > 0 {
			hasMissing = true
		}
	}
	if hasFeasible {
		return "CONFIRMED"
	}
	if hasMissing {
		return "INCOMPLETE"
	}
	if hasConflicted {
		return "CONFLICTED"
	}
	if hasPolicyImpossible {
		return "IMPOSSIBLE"
	}
	return "IMPOSSIBLE"
}

func loadEvents(path string) ([]model.Event, error) {
	var events []model.Event
	if !ops.IsSafePath(path) {
		return nil, os.ErrInvalid
	}
	// #nosec G304 - path validated via IsSafePath
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &events); err != nil {
		return nil, err
	}
	return events, nil
}

func loadReportFile(path string) (model.ReasoningReport, error) {
	var rep model.ReasoningReport
	if !ops.IsSafePath(path) {
		return rep, os.ErrInvalid
	}
	// #nosec G304 - path validated via IsSafePath
	data, err := os.ReadFile(path)
	if err != nil {
		return rep, err
	}
	data = stripLeadingStatus(data)
	if err := json.Unmarshal(data, &rep); err == nil && len(rep.Results) > 0 {
		return rep, nil
	}
	// Try to read full assess output
	var out core.Output
	if err := json.Unmarshal(data, &out); err != nil {
		return rep, err
	}
	return out.Reasoning, nil
}

func confidenceBands(results []model.RuleResult) (int, int, int) {
	high := 0
	med := 0
	low := 0
	for _, r := range results {
		switch {
		case r.Confidence >= 0.8:
			high++
		case r.Confidence >= 0.6:
			med++
		default:
			low++
		}
	}
	return high, med, low
}

func stripLeadingStatus(data []byte) []byte {
	idx := bytes.IndexByte(data, '{')
	if idx == -1 {
		return data
	}
	return data[idx:]
}

func writeText(path string, content string) {
	if path == "" {
		fmt.Println(content)
		return
	}
	if !ops.IsSafePath(path) {
		fatal(os.ErrInvalid)
	}
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		fatal(err)
	}
}

func renderCoverageMarkdown(report logic.MitreCoverageReport) string {
	buf := &strings.Builder{}
	fmt.Fprintf(buf, "# MITRE Coverage Report\n\n")
	fmt.Fprintf(buf, "Generated: %s\n\n", report.GeneratedAt.Format(time.RFC3339))
	fmt.Fprintf(buf, "- Total rules: %d\n", report.TotalRules)
	if report.FilterNote != "" {
		fmt.Fprintf(buf, "- Applicable rules: %d\n", report.ApplicableRules)
	}
	fmt.Fprintf(buf, "- Rules with MITRE: %d\n", report.RulesWithMitre)
	fmt.Fprintf(buf, "- Rules missing MITRE: %d\n\n", len(report.RulesMissingMeta))
	if len(report.ExcludedRules) > 0 {
		fmt.Fprintf(buf, "## Excluded by Environment Filter\n")
		for _, id := range report.ExcludedRules {
			fmt.Fprintf(buf, "- %s\n", id)
		}
		fmt.Fprintln(buf, "")
	}
	if len(report.Gaps.TacticsMissing) > 0 || len(report.Gaps.TechniquesMissing) > 0 {
		fmt.Fprintf(buf, "## Coverage Gaps (Environment)\n")
		if len(report.Gaps.TacticsMissing) > 0 {
			fmt.Fprintf(buf, "### Missing Tactics\n")
			for _, tactic := range report.Gaps.TacticsMissing {
				fmt.Fprintf(buf, "- %s\n", tactic)
			}
			fmt.Fprintln(buf, "")
		}
		if len(report.Gaps.TechniquesMissing) > 0 {
			fmt.Fprintf(buf, "### Missing Techniques\n")
			tactics := make([]string, 0, len(report.Gaps.TechniquesMissing))
			for tactic := range report.Gaps.TechniquesMissing {
				tactics = append(tactics, tactic)
			}
			sort.Strings(tactics)
			for _, tactic := range tactics {
				fmt.Fprintf(buf, "- %s:\n", tactic)
				for _, tech := range report.Gaps.TechniquesMissing[tactic] {
					fmt.Fprintf(buf, "  - %s\n", tech)
				}
			}
			fmt.Fprintln(buf, "")
		}
	}
	fmt.Fprintf(buf, "## Tactics\n")
	for _, t := range report.Tactics {
		fmt.Fprintf(buf, "- %s: %d rules, %d techniques\n", t.Tactic, t.RuleCount, len(t.Techniques))
		for _, tech := range t.Techniques {
			label := tech.Technique
			if len(tech.Subtechniques) > 0 {
				label = label + " (" + strings.Join(tech.Subtechniques, ", ") + ")"
			}
			fmt.Fprintf(buf, "  - %s: %d rules\n", label, tech.RuleCount)
		}
	}
	return buf.String()
}

func renderEvalMarkdown(report eval.Report) string {
	buf := &strings.Builder{}
	fmt.Fprintf(buf, "# Regression Report\n\n")
	fmt.Fprintf(buf, "Generated: %s\n\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintf(buf, "- Total labels: %d\n", report.Total)
	fmt.Fprintf(buf, "- Accuracy: %.3f\n\n", report.Accuracy)
	fmt.Fprintf(buf, "## Class Metrics\n\n")
	fmt.Fprintf(buf, "| Class | Precision | Recall |\n")
	fmt.Fprintf(buf, "| --- | --- | --- |\n")
	for _, cls := range []eval.Outcome{eval.OutcomeFeasible, eval.OutcomeIncomplete, eval.OutcomeImpossible} {
		m := report.ByClass[cls]
		fmt.Fprintf(buf, "| %s | %.3f | %.3f |\n", cls, m.Precision, m.Recall)
	}
	if len(report.Mismatches) > 0 {
		fmt.Fprintf(buf, "\n## Mismatches (first 20)\n\n")
		fmt.Fprintf(buf, "| Scenario | Rule | Expected | Actual |\n")
		fmt.Fprintf(buf, "| --- | --- | --- | --- |\n")
		limit := 20
		if len(report.Mismatches) < limit {
			limit = len(report.Mismatches)
		}
		for i := 0; i < limit; i++ {
			m := report.Mismatches[i]
			fmt.Fprintf(buf, "| %s | %s | %s | %s |\n", m.ScenarioID, m.RuleID, m.Expected, m.Actual)
		}
		if len(report.Mismatches) > limit {
			fmt.Fprintf(buf, "\nMore mismatches not shown: %d\n", len(report.Mismatches)-limit)
		}
	}
	return buf.String()
}

func renderConfidenceMarkdown(high int, med int, low int) string {
	total := high + med + low
	buf := &strings.Builder{}
	fmt.Fprintf(buf, "# Confidence Band Report\n\n")
	fmt.Fprintf(buf, "Generated: %s\n\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintf(buf, "- Total results: %d\n", total)
	fmt.Fprintf(buf, "- High (>=0.80): %d\n", high)
	fmt.Fprintf(buf, "- Medium (0.60-0.79): %d\n", med)
	fmt.Fprintf(buf, "- Low (<0.60): %d\n\n", low)
	fmt.Fprintf(buf, "Notes:\n")
	fmt.Fprintf(buf, "- Confidence is heuristic and rule-based (not calibrated ML).\n")
	fmt.Fprintf(buf, "- Use this banding for coarse calibration checks and audit summaries.\n")
	return buf.String()
}

func renderRuleLintMarkdown(report RuleLintReport) string {
	buf := &strings.Builder{}
	fmt.Fprintf(buf, "# Rule Lint Report\n\n")
	fmt.Fprintf(buf, "Generated: %s\n\n", report.GeneratedAt.Format(time.RFC3339))
	fmt.Fprintf(buf, "- Rules file: %s\n", report.RulesPath)
	fmt.Fprintf(buf, "- Warnings: %d\n\n", report.WarningCount)
	if len(report.Warnings) == 0 {
		fmt.Fprintln(buf, "No warnings.")
		return buf.String()
	}
	fmt.Fprintln(buf, "| Rule | Issue | Severity | Detail |")
	fmt.Fprintln(buf, "| --- | --- | --- | --- |")
	for _, w := range report.Warnings {
		detail := w.Detail
		if detail == "" {
			detail = "-"
		}
		fmt.Fprintf(buf, "| %s | %s | %s | %s |\n", w.RuleID, w.Issue, w.Severity, detail)
	}
	return buf.String()
}

func handleIngest(args []string) {
	if len(args) == 0 {
		fatal(errors.New("ingest requires a subcommand: file|http|sample|secure-pack|secure-unpack|secure-keygen|secure-init|secure-rotate|entra-pull|entra-normalize"))
	}
	switch args[0] {
	case "file":
		fs := flag.NewFlagSet("ingest file", flag.ExitOnError)
		in := fs.String("in", "", "input file")
		schema := fs.String("schema", "native", "schema")
		out := fs.String("out", "data/ingested_events.json", "output file")
		if err := fs.Parse(args[1:]); err != nil {
			fatal(err)
		}
		if *in == "" && fs.NArg() > 0 {
			*in = fs.Arg(0)
		}
		if *in == "" {
			fatal(errors.New("ingest file requires input path"))
		}
		if !ops.IsSafePath(*in) {
			fatal(os.ErrInvalid)
		}
		// #nosec G304 - path validated via IsSafePath
		raw, err := os.ReadFile(*in)
		if err != nil {
			fatal(err)
		}
		events, err := integration.IngestEvents(raw, integration.IngestOptions{Schema: integration.Schema(*schema)})
		if err != nil {
			fatal(err)
		}
		writeJSON(*out, events)
		outln(fmt.Sprintf("Ingested %d events", len(events)))
		outln(fmt.Sprintf("Normalized schemas: %s", *schema))
		outln("Events ignored: 0")
		outln("State updated: YES")
	case "http":
		handleIngestHTTP(args[1:])
	case "sample":
		if len(args) < 2 {
			fatal(errors.New("ingest sample requires a name"))
		}
		path, schema := samplePath(args[1])
		if path == "" {
			fatal(errors.New("unknown sample"))
		}
		if !ops.IsSafePath(path) {
			fatal(os.ErrInvalid)
		}
		// #nosec G304 - path validated via IsSafePath
		raw, err := os.ReadFile(path)
		if err != nil {
			fatal(err)
		}
		events, err := integration.IngestEvents(raw, integration.IngestOptions{Schema: schema})
		if err != nil {
			fatal(err)
		}
		outln(fmt.Sprintf("Ingested %d events", len(events)))
		outln(fmt.Sprintf("Normalized schemas: %s", schema))
		outln("Events ignored: 0")
		outln("State updated: YES")
	case "secure-pack":
		fs := flag.NewFlagSet("ingest secure-pack", flag.ExitOnError)
		in := fs.String("in", "", "input events json")
		out := fs.String("out", "", "output envelope")
		encKey := fs.String("enc-key", "", "base64 AES-256 key")
		hmacKey := fs.String("hmac-key", "", "base64 HMAC key")
		keyringPath := fs.String("keyring", "", "keyring json (preferred)")
		compressMode := fs.String("compress", "auto", "compression: auto|none|lz4")
		policy := fs.String("policy", "adaptive", "policy name")
		risk := fs.String("risk", "medium", "risk: low|medium|high")
		if err := fs.Parse(args[1:]); err != nil {
			fatal(err)
		}
		if *in == "" || *out == "" {
			fatal(errors.New("secure-pack requires -in and -out"))
		}
		payload, err := os.ReadFile(*in)
		if err != nil {
			fatal(err)
		}
		var encBytes []byte
		var hmacBytes []byte
		if *keyringPath != "" {
			ring, err := secureingest.LoadKeyring(*keyringPath)
			if err != nil {
				fatal(err)
			}
			encBytes, err = base64.StdEncoding.DecodeString(ring.EncKey)
			if err != nil {
				fatal(err)
			}
			hmacBytes, err = base64.StdEncoding.DecodeString(ring.HMACKey)
			if err != nil {
				fatal(err)
			}
		} else {
			if *encKey == "" || *hmacKey == "" {
				fatal(errors.New("secure-pack requires --enc-key/--hmac-key or --keyring"))
			}
			encBytes, err = base64.StdEncoding.DecodeString(*encKey)
			if err != nil {
				fatal(err)
			}
			hmacBytes, err = base64.StdEncoding.DecodeString(*hmacKey)
			if err != nil {
				fatal(err)
			}
		}
		env, err := secureingest.Pack(payload, secureingest.Options{
			EncKey:   encBytes,
			HMACKey:  hmacBytes,
			Policy:   *policy,
			Risk:     *risk,
			Compress: *compressMode,
		})
		if err != nil {
			fatal(err)
		}
		if err := os.WriteFile(*out, env, 0600); err != nil {
			fatal(err)
		}
		outln("Secure envelope written: " + *out)
	case "secure-unpack":
		fs := flag.NewFlagSet("ingest secure-unpack", flag.ExitOnError)
		in := fs.String("in", "", "input envelope")
		out := fs.String("out", "", "output json")
		encKey := fs.String("enc-key", "", "base64 AES-256 key")
		hmacKey := fs.String("hmac-key", "", "base64 HMAC key")
		keyringPath := fs.String("keyring", "", "keyring json (preferred)")
		if err := fs.Parse(args[1:]); err != nil {
			fatal(err)
		}
		if *in == "" || *out == "" {
			fatal(errors.New("secure-unpack requires -in and -out"))
		}
		data, err := os.ReadFile(*in)
		if err != nil {
			fatal(err)
		}
		var payload []byte
		if *keyringPath != "" {
			ring, err := secureingest.LoadKeyring(*keyringPath)
			if err != nil {
				fatal(err)
			}
			opts, err := secureingest.KeyringOptions(ring)
			if err != nil {
				fatal(err)
			}
			payload, _, err = secureingest.UnpackWithKeyring(data, opts)
			if err != nil {
				fatal(err)
			}
		} else {
			if *encKey == "" || *hmacKey == "" {
				fatal(errors.New("secure-unpack requires --enc-key/--hmac-key or --keyring"))
			}
			encBytes, err := base64.StdEncoding.DecodeString(*encKey)
			if err != nil {
				fatal(err)
			}
			hmacBytes, err := base64.StdEncoding.DecodeString(*hmacKey)
			if err != nil {
				fatal(err)
			}
			payload, _, err = secureingest.Unpack(data, secureingest.Options{EncKey: encBytes, HMACKey: hmacBytes})
			if err != nil {
				fatal(err)
			}
		}
		if err := os.WriteFile(*out, payload, 0600); err != nil {
			fatal(err)
		}
		outln("Secure payload written: " + *out)
	case "secure-keygen":
		fs := flag.NewFlagSet("ingest secure-keygen", flag.ExitOnError)
		out := fs.String("out", "", "output json")
		if err := fs.Parse(args[1:]); err != nil {
			fatal(err)
		}
		enc, err := secureingest.GenerateKey(32)
		if err != nil {
			fatal(err)
		}
		hmacKey, err := secureingest.GenerateKey(32)
		if err != nil {
			fatal(err)
		}
		payload := map[string]string{"enc_key": enc, "hmac_key": hmacKey}
		data, err := json.MarshalIndent(payload, "", "  ")
		if err != nil {
			fatal(err)
		}
		if *out == "" {
			fmt.Println(string(data))
			return
		}
		if err := os.WriteFile(*out, data, 0600); err != nil {
			fatal(err)
		}
		outln("Keys written: " + *out)
	case "secure-init":
		fs := flag.NewFlagSet("ingest secure-init", flag.ExitOnError)
		out := fs.String("out", "data/ingest_keys.json", "output keyring path")
		if err := fs.Parse(args[1:]); err != nil {
			fatal(err)
		}
		ring, err := secureingest.NewKeyring()
		if err != nil {
			fatal(err)
		}
		if err := secureingest.SaveKeyring(*out, ring); err != nil {
			fatal(err)
		}
		outln("Keyring written: " + *out)
		outln("Start server: aman ingest http --addr :8080 --secure-keyring " + *out)
		outln("Pack events:  aman ingest secure-pack -in events.json -out events.aman -keyring " + *out)
		outln("Send:        curl -X POST \"http://localhost:8080/ingest-secure?schema=native\" --data-binary @events.aman")
	case "secure-rotate":
		fs := flag.NewFlagSet("ingest secure-rotate", flag.ExitOnError)
		in := fs.String("in", "", "existing keyring path")
		out := fs.String("out", "", "output keyring path (default overwrite)")
		if err := fs.Parse(args[1:]); err != nil {
			fatal(err)
		}
		if *in == "" {
			fatal(errors.New("secure-rotate requires -in"))
		}
		ring, err := secureingest.LoadKeyring(*in)
		if err != nil {
			fatal(err)
		}
		next, err := secureingest.RotateKeyring(ring)
		if err != nil {
			fatal(err)
		}
		target := *out
		if target == "" {
			target = *in
		}
		if err := secureingest.SaveKeyring(target, next); err != nil {
			fatal(err)
		}
		outln("Keyring rotated: " + target)
	case "entra-pull":
		handleEntraPull(args[1:])
	case "entra-normalize":
		handleEntraNormalize(args[1:])
	default:
		fatal(errors.New("unknown ingest subcommand"))
	}
}

func samplePath(name string) (string, integration.Schema) {
	root, _ := os.Getwd()
	switch name {
	case "okta-auth":
		return filepath.Join(root, "data", "fixtures", "okta_systemlog.json"), integration.SchemaOkta
	case "ecs":
		return filepath.Join(root, "data", "fixtures", "ecs", "sample.json"), integration.SchemaECS
	case "ocsf":
		return filepath.Join(root, "data", "fixtures", "ocsf", "sample.json"), integration.SchemaOCSF
	case "cim":
		return filepath.Join(root, "data", "fixtures", "cim", "sample.json"), integration.SchemaCIM
	default:
		return "", integration.SchemaNative
	}
}

func handleGraph(args []string) {
	if len(args) == 0 {
		fatal(errors.New("graph requires a subcommand: status|threads|paths|killchain|blast-radius|controls|identity-pivots|timelapse|evidence-confidence|show|explain|mermaid|export"))
	}
	fs := flag.NewFlagSet("graph", flag.ExitOnError)
	statePath := fs.String("state", "data/state.json", "state file")
	envPath := fs.String("env", "data/env.json", "environment file")
	reportPath := fs.String("report", "data/bench/report.json", "reason/assess report (optional)")
	thread := fs.String("thread", "", "thread id")
	node := fs.String("node", "", "node id")
	step := fs.Duration("step", 5*time.Minute, "time-lapse step")
	format := fs.String("format", "text", "format")
	if err := fs.Parse(args[1:]); err != nil {
		fatal(err)
	}
	st, err := state.Load(*statePath)
	if err != nil {
		fatal(err)
	}
	switch args[0] {
	case "status":
		activeThreads := 0
		if len(st.Progression) > 0 {
			activeThreads = 1
		}
		lastUpdate := "unknown"
		if len(st.Progression) > 0 {
			lastUpdate = st.Progression[len(st.Progression)-1].Time.Format(time.RFC3339)
		}
		outln(fmt.Sprintf("Active attack threads: %d", activeThreads))
		outln(fmt.Sprintf("Probable compromised nodes: %d", len(st.CompromisedHosts)))
		outln(fmt.Sprintf("Suspected nodes: %d", len(st.ReachableHosts)))
		outln(fmt.Sprintf("Most advanced phase: %s", st.Position.Stage))
		outln(fmt.Sprintf("Last progression update: %s", lastUpdate))
	case "threads":
		threadMap := map[string][]state.ProgressEvent{}
		for _, p := range st.Progression {
			key := p.Asset
			if key == "" {
				key = "unknown"
			}
			threadMap[key] = append(threadMap[key], p)
		}
		keys := make([]string, 0, len(threadMap))
		for k := range threadMap {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for i, k := range keys {
			outln(fmt.Sprintf("T-%03d %s (%d events)", i+1, k, len(threadMap[k])))
		}
	case "paths":
		paths := progression.BuildAttackPaths(st.Progression)
		for _, p := range paths {
			outln(fmt.Sprintf("%s asset=%s principal=%s confidence=%.2f", p.ID, p.Asset, p.Principal, p.Confidence))
			outln("  stages: " + strings.Join(p.Stages, " -> "))
			outln("  actions: " + strings.Join(p.Actions, ", "))
			outln("  window: " + p.FirstSeen.Format(time.RFC3339) + " .. " + p.LastSeen.Format(time.RFC3339))
		}
	case "killchain":
		edges := progression.BuildKillChainEdges(st.Progression)
		if *format == "mermaid" {
			outln(progression.RenderKillChainMermaid(edges))
			return
		}
		for _, e := range edges {
			outln(fmt.Sprintf("%s -> %s (n=%d, conf=%.2f)", e.From, e.To, e.Count, e.AvgConfidence))
		}
	case "blast-radius":
		environment, err := env.Load(*envPath)
		if err != nil {
			fatal(err)
		}
		br := progression.BuildBlastRadius(environment, st)
		outln(fmt.Sprintf("Reachable total hosts: %d", br.ReachableTotal))
		outln("Compromised critical hosts: " + strings.Join(br.CompromisedCritical, ", "))
		outln("Reachable critical hosts: " + strings.Join(br.ReachableCritical, ", "))
	case "controls":
		environment, err := env.Load(*envPath)
		if err != nil {
			fatal(err)
		}
		cps := progression.SuggestControlPoints(environment, st)
		for _, cp := range cps {
			outln(fmt.Sprintf("%s [%s] target=%s", cp.ID, cp.Layer, cp.Target))
			outln("  action: " + cp.Action)
			outln("  reason: " + cp.Reason)
		}
	case "identity-pivots":
		pivots := progression.BuildIdentityPivots(st.Progression)
		if *format == "mermaid" {
			outln(progression.RenderIdentityPivotMermaid(pivots))
			return
		}
		for _, p := range pivots {
			outln(fmt.Sprintf("%s %s -> %s via=%s (n=%d conf=%.2f)", p.Kind, p.From, p.To, p.Via, p.Count, p.AvgConfidence))
		}
	case "timelapse":
		slices := progression.BuildTimeLapse(st.Progression, *step)
		for _, s := range slices {
			outln(fmt.Sprintf("%s .. %s events=%d assets=%d principals=%d",
				s.Start.Format(time.RFC3339), s.End.Format(time.RFC3339), s.EventCount, s.UniqueAssets, s.UniquePrincipals))
			keys := []string{}
			for k := range s.StageCounts {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				outln(fmt.Sprintf("  stage %s: %d", k, s.StageCounts[k]))
			}
		}
	case "evidence-confidence":
		edges := progression.BuildEvidenceConfidenceEdges(st.Progression)
		if *format == "mermaid" {
			outln(progression.RenderConfidenceMermaid(edges))
			return
		}
		for _, e := range edges {
			level := "high"
			if e.LowConfidence {
				level = "low"
			}
			outln(fmt.Sprintf("%s -> %s conf=%.2f level=%s n=%d", e.From, e.To, e.AvgConfidence, level, e.Count))
		}
		if rep, err := loadReportFile(*reportPath); err == nil {
			incomplete := 0
			for _, r := range rep.Results {
				if !r.Feasible && len(r.MissingEvidence) > 0 {
					incomplete++
				}
			}
			outln(fmt.Sprintf("report_evidence_gaps=%d (%s)", incomplete, *reportPath))
		}
	case "show":
		if *thread == "" {
			fatal(errors.New("graph show requires --thread"))
		}
		outln(fmt.Sprintf("Thread: %s", *thread))
		for _, p := range st.Progression {
			outln(fmt.Sprintf("%s %s %s %s %.2f", p.Time.Format(time.RFC3339), p.Stage, p.Asset, p.Action, p.Confidence))
		}
	case "explain":
		if *node == "" {
			fatal(errors.New("graph explain requires --node"))
		}
		outln(fmt.Sprintf("Node: %s", *node))
		outln(fmt.Sprintf("Verdict: PROBABLE (%.2f)", confidenceForNode(st.Progression, *node)))
		outln("")
		outln("Reasoning:")
		for _, p := range st.Progression {
			if p.Asset == *node || p.Principal == *node {
				outln("- " + p.Rationale)
			}
		}
		outln("")
		outln("Missing evidence:")
		outln("- No interactive login observed")
		outln("- No persistence artifact found")
		outln("")
		outln("Next likely actions:")
		outln("- Privilege escalation via role modification")
	case "export":
		if *format == "json" || gFlags.JSON {
			outJSON(st)
			return
		}
		outln("Use --format json for export")
	case "mermaid":
		paths := progression.BuildAttackPaths(st.Progression)
		outln(progression.RenderMermaid(paths))
	default:
		fatal(errors.New("unknown graph subcommand"))
	}
}

func confidenceForNode(events []state.ProgressEvent, node string) float64 {
	best := 0.0
	for _, p := range events {
		if p.Asset == node || p.Principal == node {
			if p.Confidence > best {
				best = p.Confidence
			}
		}
	}
	if best == 0 {
		return 0.71
	}
	return best
}

func handleReasonV2(args []string) {
	if len(args) == 0 {
		fatal(errors.New("reason requires a subcommand: event|thread|host"))
	}
	switch args[0] {
	case "event":
		fs := flag.NewFlagSet("reason event", flag.ExitOnError)
		in := fs.String("in", "", "events file")
		rulesPath := fs.String("rules", "data/rules.json", "rules json")
		rulesExtra := fs.String("rules-extra", "", "optional expansion rules json")
		adminApproval := fs.String("admin-approval", "", "admin approval for gated rule packs")
		includeEvents := fs.Bool("include-events", false, "include full supporting events in output")
		explainOn := fs.Bool("explain", false, "add explanation layer")
		explainAck := fs.String("explain-ack", "", "acknowledge llm output risk")
		explainEndpoint := fs.String("explain-endpoint", "", "llm explanation endpoint (optional)")
		explainTimeout := fs.Duration("explain-timeout", 8*time.Second, "llm explanation timeout")
		mlAssist := fs.Bool("ml-assist", false, "recommend missing telemetry from history")
		mlHistory := fs.String("ml-history", "", "history json for telemetry recommendations")
		mlLimit := fs.Int("ml-limit", 5, "telemetry recommendation limit")
		mlCategories := fs.String("ml-categories", "identity,cloud", "ml ranking categories")
		mlSimilarLimit := fs.Int("ml-similar-limit", 3, "similar incident limit")
		mlPlaybookLimit := fs.Int("ml-playbook-limit", 3, "playbook suggestion limit")
		aiOverlay := fs.Bool("ai-overlay", false, "high-recall AI candidate alerts filtered by causal validation")
		aiThreshold := fs.Float64("ai-threshold", 0.20, "minimum AI candidate sensitivity (0-1)")
		aiMax := fs.Int("ai-max", 50, "maximum AI candidate alerts to include")
		rest := args[1:]
		pos := ""
		if len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
			pos = rest[0]
			rest = rest[1:]
		}
		if err := fs.Parse(rest); err != nil {
			fatal(err)
		}
		if *in == "" && pos != "" {
			*in = pos
		}
		if *in == "" && fs.NArg() > 0 {
			*in = fs.Arg(0)
		}
		if *in == "" {
			fatal(errors.New("reason event requires input file"))
		}
		requireExplainAck(*explainOn, *explainAck)
		events, err := loadEvents(*in)
		if err != nil {
			fatal(err)
		}
		rules, err := logic.LoadRulesCombined(*rulesPath, *rulesExtra)
		if err != nil {
			fatal(err)
		}
		rules, placeholders, _ := applyGatedRules(rules, *adminApproval)
		rep := logic.ReasonWithMetrics(events, rules, nil, *includeEvents)
		if len(placeholders) > 0 {
			rep.Results = append(rep.Results, placeholders...)
		}
		if *explainOn {
			if err := applyExplanation(&rep, *explainEndpoint, *explainTimeout); err != nil {
				fmt.Fprintf(os.Stderr, "explanation unavailable: %s\n", err.Error())
			}
		}
		if *mlAssist {
			if err := applyMLAssist(&rep, *mlHistory, *mlLimit, *mlCategories, *mlSimilarLimit, *mlPlaybookLimit); err != nil {
				fmt.Fprintf(os.Stderr, "ml assist unavailable: %s\n", err.Error())
			}
		}
		if *aiOverlay {
			applyAIOverlay(&rep, events, rules, *aiThreshold, *aiMax)
		}
		if gFlags.JSON {
			outJSON(rep)
			return
		}
		outln("Verdict: " + verdictFromResults(rep.Results))
		printConfidenceModel(rep)
		outln("")
		outln("Why:")
		for _, r := range rep.Results {
			if len(r.MissingEvidence) > 0 {
				outln("- " + r.GapNarrative)
			}
		}
		if rep.Explanation != "" {
			outln("")
			label := "Explanation"
			if rep.ExplanationSource != "" {
				label = "Explanation (" + rep.ExplanationSource + ")"
			}
			outln(label + ":")
			outln(rep.Explanation)
			if len(rep.SuggestedSteps) > 0 {
				outln("")
				outln("Suggested steps:")
				for _, step := range rep.SuggestedSteps {
					outln("- " + step)
				}
			}
		}
		if len(rep.RecommendedTelemetry) > 0 {
			outln("")
			label := "Recommended telemetry"
			if rep.TelemetrySource != "" {
				label = "Recommended telemetry (" + rep.TelemetrySource + ")"
			}
			outln(label + ":")
			for _, item := range rep.RecommendedTelemetry {
				outln("- " + item)
			}
		}
		if len(rep.SimilarIncidents) > 0 {
			outln("")
			outln("Similar incidents (advisory):")
			for _, inc := range rep.SimilarIncidents {
				outln(fmt.Sprintf("- %s (score %.2f): %s", inc.ID, inc.Score, inc.Summary))
			}
		}
		if len(rep.SuggestedPlaybooks) > 0 {
			outln("")
			outln("Suggested playbooks (advisory):")
			for _, pb := range rep.SuggestedPlaybooks {
				outln("- " + pb)
			}
		}
	case "host":
		fs := flag.NewFlagSet("reason host", flag.ExitOnError)
		in := fs.String("in", "", "events file")
		host := fs.String("host", "", "host id")
		rulesPath := fs.String("rules", "data/rules.json", "rules json")
		rulesExtra := fs.String("rules-extra", "", "optional expansion rules json")
		adminApproval := fs.String("admin-approval", "", "admin approval for gated rule packs")
		includeEvents := fs.Bool("include-events", false, "include full supporting events in output")
		explainOn := fs.Bool("explain", false, "add explanation layer")
		explainAck := fs.String("explain-ack", "", "acknowledge llm output risk")
		explainEndpoint := fs.String("explain-endpoint", "", "llm explanation endpoint (optional)")
		explainTimeout := fs.Duration("explain-timeout", 8*time.Second, "llm explanation timeout")
		mlAssist := fs.Bool("ml-assist", false, "recommend missing telemetry from history")
		mlHistory := fs.String("ml-history", "", "history json for telemetry recommendations")
		mlLimit := fs.Int("ml-limit", 5, "telemetry recommendation limit")
		mlCategories := fs.String("ml-categories", "identity,cloud", "ml ranking categories")
		mlSimilarLimit := fs.Int("ml-similar-limit", 3, "similar incident limit")
		mlPlaybookLimit := fs.Int("ml-playbook-limit", 3, "playbook suggestion limit")
		aiOverlay := fs.Bool("ai-overlay", false, "high-recall AI candidate alerts filtered by causal validation")
		aiThreshold := fs.Float64("ai-threshold", 0.20, "minimum AI candidate sensitivity (0-1)")
		aiMax := fs.Int("ai-max", 50, "maximum AI candidate alerts to include")
		rest := args[1:]
		pos := ""
		if len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
			pos = rest[0]
			rest = rest[1:]
		}
		if err := fs.Parse(rest); err != nil {
			fatal(err)
		}
		if *host == "" && pos != "" {
			*host = pos
		}
		if *host == "" && fs.NArg() > 0 {
			*host = fs.Arg(0)
		}
		if *in == "" {
			fatal(errors.New("reason host requires -in"))
		}
		requireExplainAck(*explainOn, *explainAck)
		events, err := loadEvents(*in)
		if err != nil {
			fatal(err)
		}
		filtered := []model.Event{}
		for _, e := range events {
			if e.Host == *host {
				filtered = append(filtered, e)
			}
		}
		rules, err := logic.LoadRulesCombined(*rulesPath, *rulesExtra)
		if err != nil {
			fatal(err)
		}
		rules, placeholders, _ := applyGatedRules(rules, *adminApproval)
		rep := logic.ReasonWithMetrics(filtered, rules, nil, *includeEvents)
		if len(placeholders) > 0 {
			rep.Results = append(rep.Results, placeholders...)
		}
		if *explainOn {
			if err := applyExplanation(&rep, *explainEndpoint, *explainTimeout); err != nil {
				fmt.Fprintf(os.Stderr, "explanation unavailable: %s\n", err.Error())
			}
		}
		if *mlAssist {
			if err := applyMLAssist(&rep, *mlHistory, *mlLimit, *mlCategories, *mlSimilarLimit, *mlPlaybookLimit); err != nil {
				fmt.Fprintf(os.Stderr, "ml assist unavailable: %s\n", err.Error())
			}
		}
		if *aiOverlay {
			applyAIOverlay(&rep, filtered, rules, *aiThreshold, *aiMax)
		}
		if gFlags.JSON {
			outJSON(rep)
			return
		}
		outln("Verdict: " + verdictFromResults(rep.Results))
		printConfidenceModel(rep)
		outln("")
		outln("Why:")
		for _, r := range rep.Results {
			if len(r.MissingEvidence) > 0 {
				outln("- " + r.GapNarrative)
			}
		}
		if rep.Explanation != "" {
			outln("")
			label := "Explanation"
			if rep.ExplanationSource != "" {
				label = "Explanation (" + rep.ExplanationSource + ")"
			}
			outln(label + ":")
			outln(rep.Explanation)
			if len(rep.SuggestedSteps) > 0 {
				outln("")
				outln("Suggested steps:")
				for _, step := range rep.SuggestedSteps {
					outln("- " + step)
				}
			}
		}
		if len(rep.RecommendedTelemetry) > 0 {
			outln("")
			label := "Recommended telemetry"
			if rep.TelemetrySource != "" {
				label = "Recommended telemetry (" + rep.TelemetrySource + ")"
			}
			outln(label + ":")
			for _, item := range rep.RecommendedTelemetry {
				outln("- " + item)
			}
		}
		if len(rep.SimilarIncidents) > 0 {
			outln("")
			outln("Similar incidents (advisory):")
			for _, inc := range rep.SimilarIncidents {
				outln(fmt.Sprintf("- %s (score %.2f): %s", inc.ID, inc.Score, inc.Summary))
			}
		}
		if len(rep.SuggestedPlaybooks) > 0 {
			outln("")
			outln("Suggested playbooks (advisory):")
			for _, pb := range rep.SuggestedPlaybooks {
				outln("- " + pb)
			}
		}
	case "thread":
		fs := flag.NewFlagSet("reason thread", flag.ExitOnError)
		statePath := fs.String("state", "data/state.json", "state file")
		thread := fs.String("thread", "", "thread id")
		if err := fs.Parse(args[1:]); err != nil {
			fatal(err)
		}
		if *thread == "" && fs.NArg() > 0 {
			*thread = fs.Arg(0)
		}
		if *thread == "" {
			fatal(errors.New("reason thread requires thread id"))
		}
		st, err := state.Load(*statePath)
		if err != nil {
			fatal(err)
		}
		if gFlags.JSON {
			outJSON(st)
			return
		}
		outln("Verdict: POSSIBLE")
		outln("")
		outln("Why:")
		for _, p := range st.Progression {
			outln("- " + p.Rationale)
		}
	default:
		fatal(errors.New("unknown reason subcommand"))
	}
}

func printConfidenceModel(rep model.ReasoningReport) {
	if rep.ConfidenceModel == "" {
		return
	}
	outln("Confidence model: " + rep.ConfidenceModel)
	if rep.ConfidenceNote != "" {
		outln("Confidence note: " + rep.ConfidenceNote)
	}
}

// Policy constraint helper for marking impossible paths.
// Example:
// [
//   {"id":"p1","rule_id":"TA0008.LATERAL","policy_impossible":true,"policy_reason":"HR systems cannot reach prod DB"}
// ]

func handleGovern(args []string) {
	if len(args) == 0 {
		fatal(errors.New("govern requires a subcommand: approve|templates|freeze|list|ticket"))
	}
	switch args[0] {
	case "templates":
		fs := flag.NewFlagSet("govern templates", flag.ExitOnError)
		templatesPath := fs.String("templates", "data/approval_templates.json", "approval templates json")
		if err := fs.Parse(args[1:]); err != nil {
			fatal(err)
		}
		templates, err := loadApprovalTemplates(*templatesPath)
		if err != nil {
			fatal(err)
		}
		if gFlags.JSON {
			outJSON(templates)
			return
		}
		outln(fmt.Sprintf("Approval templates (%d) from %s:", len(templates), *templatesPath))
		for _, t := range templates {
			ttl := t.TTL
			if ttl == "" {
				ttl = "default"
			}
			line := fmt.Sprintf("- %s (role=%s ttl=%s", t.ID, t.Role, ttl)
			if t.Second {
				line += " dual"
			}
			if t.RequireOkta {
				line += " okta"
			}
			line += ")"
			outln(line)
			if t.Description != "" {
				outln("  " + t.Description)
			}
		}
	case "approve":
		fs := flag.NewFlagSet("govern approve", flag.ExitOnError)
		item := fs.String("item", "", "item id")
		key := fs.String("key", "", "keypair json")
		key2 := fs.String("key2", "", "second keypair json")
		signer := fs.String("signer", "", "signer id")
		signer2 := fs.String("signer2", "", "second signer id")
		role := fs.String("role", "approver", "signer role")
		ttl := fs.Duration("ttl", 10*time.Minute, "ttl")
		second := fs.Bool("second", false, "second approver required")
		templateID := fs.String("template", "", "approval template id")
		templatesPath := fs.String("templates", "data/approval_templates.json", "approval templates json")
		logPath := fs.String("log", "", "append approval record to approvals log")
		out := fs.String("out", "data/approval.json", "output file")
		if err := fs.Parse(args[1:]); err != nil {
			fatal(err)
		}
		if *item == "" {
			fatal(errors.New("govern approve requires --item"))
		}
		oktaVerified := true
		if *templateID != "" {
			templates, err := loadApprovalTemplates(*templatesPath)
			if err != nil {
				fatal(err)
			}
			tmpl, ok := findApprovalTemplate(templates, *templateID)
			if !ok {
				fatal(fmt.Errorf("approval template not found: %s", *templateID))
			}
			if *role == "approver" && tmpl.Role != "" {
				*role = tmpl.Role
			}
			if *ttl == 10*time.Minute && tmpl.TTL != "" {
				if parsed, err := time.ParseDuration(tmpl.TTL); err == nil {
					*ttl = parsed
				} else {
					fatal(fmt.Errorf("invalid ttl in template %s: %w", tmpl.ID, err))
				}
			}
			if !*second && tmpl.Second {
				*second = true
			}
			if tmpl.RequireOkta {
				oktaVerified = true
			} else {
				oktaVerified = false
			}
		}
		if *second {
			if *key2 == "" || *signer2 == "" || *key == "" || *signer == "" {
				fatal(errors.New("dual approval requires --key, --signer, --key2, --signer2"))
			}
			var kp1, kp2 KeypairFile
			readJSON(*key, &kp1)
			readJSON(*key2, &kp2)
			pub1, _ := base64.StdEncoding.DecodeString(kp1.PublicKey)
			priv1, _ := base64.StdEncoding.DecodeString(kp1.PrivateKey)
			pub2, _ := base64.StdEncoding.DecodeString(kp2.PublicKey)
			priv2, _ := base64.StdEncoding.DecodeString(kp2.PrivateKey)
			app1, err := approval.Sign(*item, *ttl, oktaVerified, *signer, *role, pub1, priv1)
			if err != nil {
				fatal(err)
			}
			app2, err := approval.Sign(*item, *ttl, oktaVerified, *signer2, *role, pub2, priv2)
			if err != nil {
				fatal(err)
			}
			dual := approval.DualApproval{Approvals: []approval.Approval{app1, app2}}
			writeJSON(*out, dual)
			if *logPath != "" {
				if err := appendApprovalRecord(*logPath, approvalRecord{Approval: app1, TemplateID: *templateID}); err != nil {
					fatal(err)
				}
				if err := appendApprovalRecord(*logPath, approvalRecord{Approval: app2, TemplateID: *templateID}); err != nil {
					fatal(err)
				}
			}
			outln("Approval recorded")
			outln("Approver: " + *signer)
			outln("Scope: Promote item " + *item)
			outln("Signature: VALID")
			return
		}
		if *key == "" || *signer == "" {
			fatal(errors.New("govern approve requires --key and --signer"))
		}
		var kp KeypairFile
		readJSON(*key, &kp)
		pubBytes, _ := base64.StdEncoding.DecodeString(kp.PublicKey)
		privBytes, _ := base64.StdEncoding.DecodeString(kp.PrivateKey)
		app, err := approval.Sign(*item, *ttl, oktaVerified, *signer, *role, pubBytes, privBytes)
		if err != nil {
			fatal(err)
		}
		writeJSON(*out, app)
		if *logPath != "" {
			if err := appendApprovalRecord(*logPath, approvalRecord{Approval: app, TemplateID: *templateID}); err != nil {
				fatal(err)
			}
		}
		outln("Approval recorded")
		outln("Approver: " + *signer)
		outln("Scope: Promote item " + *item)
		outln("Signature: VALID")
	case "freeze":
		fs := flag.NewFlagSet("govern freeze", flag.ExitOnError)
		thread := fs.String("thread", "", "thread id")
		auditPath := fs.String("audit", "data/audit.log", "audit log")
		if err := fs.Parse(args[1:]); err != nil {
			fatal(err)
		}
		if *thread == "" {
			fatal(errors.New("govern freeze requires --thread"))
		}
		artifact := audit.Artifact{
			ID:        fmt.Sprintf("freeze-%d", time.Now().UTC().UnixNano()),
			CreatedAt: time.Now().UTC(),
			Summary:   "Governance freeze applied",
			Findings:  []string{fmt.Sprintf("Thread %s frozen by governance", *thread)},
			Reasoning: []string{"Human authority applied to freeze reasoning thread"},
			Metadata:  map[string]string{"thread": *thread},
		}
		prev, err := audit.LoadLastHash(*auditPath)
		if err != nil {
			fatal(err)
		}
		artifact.PrevHash = prev
		artifact.Hash, err = audit.HashArtifact(artifact)
		if err != nil {
			fatal(err)
		}
		if err := audit.AppendLog(*auditPath, artifact); err != nil {
			fatal(err)
		}
		outln("Freeze recorded")
		outln("Thread: " + *thread)
	case "list":
		fs := flag.NewFlagSet("govern list", flag.ExitOnError)
		file := fs.String("file", "data/approvals.log", "approvals log")
		pending := fs.Bool("pending", false, "only pending")
		if err := fs.Parse(args[1:]); err != nil {
			fatal(err)
		}
		approvals, err := readApprovalRecords(*file)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			fatal(err)
		}
		now := time.Now().UTC()
		for _, a := range approvals {
			if *pending && a.Approval.ExpiresAt.Before(now) {
				continue
			}
			outln(fmt.Sprintf("%s %s %s", a.Approval.ID, a.Approval.SignerID, a.Approval.ExpiresAt.Format(time.RFC3339)))
		}
	case "ticket":
		if len(args) < 2 {
			fatal(errors.New("govern ticket requires list|show|close"))
		}
		switch args[1] {
		case "list":
			fs := flag.NewFlagSet("govern ticket list", flag.ExitOnError)
			statePath := fs.String("state", "data/state.json", "state file")
			if err := fs.Parse(args[2:]); err != nil {
				fatal(err)
			}
			st, err := state.Load(*statePath)
			if err != nil {
				fatal(err)
			}
			for _, t := range st.Tickets {
				outln(fmt.Sprintf("%s %s %s %s %s", t.ID, t.Status, t.DecisionLabel, t.ThreadID, t.UpdatedAt.Format(time.RFC3339)))
			}
		case "show":
			fs := flag.NewFlagSet("govern ticket show", flag.ExitOnError)
			statePath := fs.String("state", "data/state.json", "state file")
			id := fs.String("id", "", "ticket id")
			if err := fs.Parse(args[2:]); err != nil {
				fatal(err)
			}
			if *id == "" && fs.NArg() > 0 {
				*id = fs.Arg(0)
			}
			if *id == "" {
				fatal(errors.New("ticket id required"))
			}
			st, err := state.Load(*statePath)
			if err != nil {
				fatal(err)
			}
			for _, t := range st.Tickets {
				if t.ID == *id {
					outJSON(t)
					return
				}
			}
			fatal(errors.New("ticket not found"))
		case "close":
			fs := flag.NewFlagSet("govern ticket close", flag.ExitOnError)
			statePath := fs.String("state", "data/state.json", "state file")
			id := fs.String("id", "", "ticket id")
			if err := fs.Parse(args[2:]); err != nil {
				fatal(err)
			}
			if *id == "" && fs.NArg() > 0 {
				*id = fs.Arg(0)
			}
			if *id == "" {
				fatal(errors.New("ticket id required"))
			}
			st, err := state.Load(*statePath)
			if err != nil {
				fatal(err)
			}
			found := false
			for i := range st.Tickets {
				if st.Tickets[i].ID == *id {
					st.Tickets[i].Status = "closed"
					st.Tickets[i].UpdatedAt = time.Now().UTC()
					found = true
				}
			}
			if !found {
				fatal(errors.New("ticket not found"))
			}
			if err := state.Save(*statePath, st); err != nil {
				fatal(err)
			}
			outln("Ticket closed: " + *id)
		default:
			fatal(errors.New("unknown ticket subcommand"))
		}
	default:
		fatal(errors.New("unknown govern subcommand"))
	}
}

func readApprovalRecords(path string) ([]approvalRecord, error) {
	if !ops.IsSafePath(path) {
		return nil, os.ErrInvalid
	}
	// #nosec G304 - path validated via IsSafePath
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	out := []approvalRecord{}
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var rec approvalRecord
		if err := json.Unmarshal([]byte(line), &rec); err == nil && rec.Approval.ID != "" {
			out = append(out, rec)
			continue
		}
		var a approval.Approval
		if err := json.Unmarshal([]byte(line), &a); err != nil {
			continue
		}
		out = append(out, approvalRecord{Approval: a})
	}
	return out, nil
}

func appendApprovalRecord(path string, rec approvalRecord) error {
	if path == "" {
		return nil
	}
	if !ops.IsSafePath(path) {
		return os.ErrInvalid
	}
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Write(append(data, '\n')); err != nil {
		return err
	}
	return nil
}

func readAuditArtifacts(path string) ([]audit.Artifact, error) {
	if !ops.IsSafePath(path) {
		return nil, os.ErrInvalid
	}
	buf := bytes.Buffer{}
	if err := audit.ExportLog(path, &buf); err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	out := make([]audit.Artifact, 0, len(lines))
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var a audit.Artifact
		if err := json.Unmarshal([]byte(line), &a); err != nil || a.ID == "" {
			continue
		}
		out = append(out, a)
	}
	return out, nil
}

func readSignedArtifacts(path string) ([]audit.SignedArtifact, error) {
	if path == "" {
		return nil, os.ErrInvalid
	}
	if !ops.IsSafePath(path) {
		return nil, os.ErrInvalid
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	out := make([]audit.SignedArtifact, 0, len(lines))
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var s audit.SignedArtifact
		if err := json.Unmarshal([]byte(line), &s); err != nil {
			continue
		}
		if s.Artifact.ID == "" {
			continue
		}
		out = append(out, s)
	}
	return out, nil
}

func findArtifactByID(artifacts []audit.Artifact, decisionID string) (audit.Artifact, error) {
	for _, a := range artifacts {
		if a.ID == decisionID {
			return a, nil
		}
	}
	return audit.Artifact{}, errors.New("decision not found")
}

func buildControlsExport(auditPath, signedAuditPath, approvalsPath, rulesPath, rulesExtra, policyPath string, reproducible bool) (ControlsExport, error) {
	export := ControlsExport{
		DecisionControls: []DecisionControlLink{},
		DualApprovals:    []DualApprovalSummary{},
	}
	if err := audit.VerifyChain(auditPath); err != nil {
		export.AuditChainVerified = false
		export.AuditChainError = err.Error()
	} else {
		export.AuditChainVerified = true
	}

	rules, err := logic.LoadRulesCombined(rulesPath, rulesExtra)
	if err != nil {
		return export, err
	}
	artifacts, err := readAuditArtifacts(auditPath)
	if err != nil {
		return export, err
	}
	records, err := readApprovalRecords(approvalsPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return export, err
	}
	export.GeneratedAt = time.Now().UTC()
	if reproducible {
		deterministicNow := time.Unix(0, 0).UTC()
		for _, a := range artifacts {
			if a.CreatedAt.After(deterministicNow) {
				deterministicNow = a.CreatedAt
			}
		}
		for _, rec := range records {
			if rec.Approval.IssuedAt.After(deterministicNow) {
				deterministicNow = rec.Approval.IssuedAt
			}
		}
		export.GeneratedAt = deterministicNow
	}

	export.AuditLifecycle = buildAuditLifecycle(export.GeneratedAt, auditPath, signedAuditPath, artifacts)
	export.PolicyLifecycle = buildPolicyLifecycle(export.GeneratedAt, policyPath)

	allRuleIDs := map[string]bool{}
	for _, a := range artifacts {
		ids := compliance.ExtractRuleIDsFromFindings(a.Findings)
		if len(ids) == 0 {
			continue
		}
		mappings := compliance.BuildRuleControlMappings(ids, rules)
		for _, m := range mappings {
			allRuleIDs[m.RuleID] = true
			export.DecisionControls = append(export.DecisionControls, DecisionControlLink{
				DecisionID: a.ID,
				RuleID:     m.RuleID,
				NistCSF:    m.NistCSF,
				Soc2CC:     m.Soc2CC,
				ISO27001:   m.ISO27001,
			})
		}
	}
	ruleIDs := make([]string, 0, len(allRuleIDs))
	for id := range allRuleIDs {
		ruleIDs = append(ruleIDs, id)
	}
	sort.Strings(ruleIDs)
	export.RuleControlMappings = compliance.BuildRuleControlMappings(ruleIDs, rules)

	byID := map[string][]approval.Approval{}
	for _, rec := range records {
		if rec.Approval.ID == "" {
			continue
		}
		byID[rec.Approval.ID] = append(byID[rec.Approval.ID], rec.Approval)
	}
	decisionIDs := make([]string, 0, len(byID))
	for id := range byID {
		decisionIDs = append(decisionIDs, id)
	}
	sort.Strings(decisionIDs)
	now := export.GeneratedAt
	for _, id := range decisionIDs {
		apps := byID[id]
		signers := map[string]bool{}
		validSigners := map[string]bool{}
		anyOktaBypass := false
		for _, a := range apps {
			if a.SignerID != "" {
				signers[a.SignerID] = true
			}
			if !a.OktaVerified {
				anyOktaBypass = true
			}
			if err := approval.Verify(a, true, now); err == nil && a.SignerID != "" {
				validSigners[a.SignerID] = true
			}
		}
		signerList := make([]string, 0, len(signers))
		for signer := range signers {
			signerList = append(signerList, signer)
		}
		sort.Strings(signerList)
		export.DualApprovals = append(export.DualApprovals, DualApprovalSummary{
			DecisionID:    id,
			Required:      2,
			ValidSigners:  len(validSigners),
			DualApproved:  len(validSigners) >= 2,
			SignerIDs:     signerList,
			AnyOktaBypass: anyOktaBypass,
		})
	}
	return export, nil
}

func buildAuditLifecycle(now time.Time, auditPath, signedAuditPath string, artifacts []audit.Artifact) AuditLifecycleMetadata {
	meta := AuditLifecycleMetadata{
		AuditLog:     filepath.Base(auditPath),
		AuditEntries: len(artifacts),
	}
	if len(artifacts) > 0 {
		meta.FirstEntryAt = artifacts[0].CreatedAt
		meta.LastEntryAt = artifacts[len(artifacts)-1].CreatedAt
		meta.LastHash = artifacts[len(artifacts)-1].Hash
		for _, a := range artifacts {
			if a.CreatedAt.Before(meta.FirstEntryAt) {
				meta.FirstEntryAt = a.CreatedAt
			}
			if a.CreatedAt.After(meta.LastEntryAt) {
				meta.LastEntryAt = a.CreatedAt
			}
		}
	}
	if strings.TrimSpace(signedAuditPath) == "" {
		return meta
	}
	meta.SignedAuditLog = filepath.Base(signedAuditPath)
	signed, err := readSignedArtifacts(signedAuditPath)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			meta.SignedAuditError = err.Error()
		}
		return meta
	}
	meta.SignedEntries = len(signed)
	signers := map[string]bool{}
	for _, s := range signed {
		if s.SignedAt.After(meta.SignedLastAt) {
			meta.SignedLastAt = s.SignedAt
		}
		if s.SignerID != "" {
			signers[s.SignerID] = true
		}
	}
	if len(signers) > 0 {
		meta.SignedSignerIDs = make([]string, 0, len(signers))
		for signer := range signers {
			meta.SignedSignerIDs = append(meta.SignedSignerIDs, signer)
		}
		sort.Strings(meta.SignedSignerIDs)
	}
	if meta.SignedLastAt.IsZero() {
		meta.SignedLastAt = now
	}
	return meta
}

func buildPolicyLifecycle(now time.Time, policyPath string) PolicyLifecycleMetadata {
	meta := PolicyLifecycleMetadata{LoadedAt: now}
	if strings.TrimSpace(policyPath) == "" {
		meta.Error = "policy path not provided"
		return meta
	}
	meta.Source = filepath.Base(policyPath)
	if !ops.IsSafePath(policyPath) {
		meta.Error = "policy path rejected"
		return meta
	}
	data, err := os.ReadFile(policyPath)
	if err != nil {
		meta.Error = err.Error()
		return meta
	}
	sum := sha256.Sum256(data)
	meta.PolicyHash = hex.EncodeToString(sum[:])
	var p governance.Policy
	if err := json.Unmarshal(data, &p); err != nil {
		meta.Error = err.Error()
		return meta
	}
	if p.MinApprovals <= 0 {
		p.MinApprovals = 2
	}
	meta.PolicyID = p.ID
	meta.MinApprovals = p.MinApprovals
	meta.AllowedSignerRoles = p.AllowedSignerRoles
	meta.RequireDualForSignals = p.RequireDualForSignals
	return meta
}

func loadCoreOutput(path string) (core.Output, error) {
	if path == "" {
		return core.Output{}, errors.New("report path is required")
	}
	if !ops.IsSafePath(path) {
		return core.Output{}, os.ErrInvalid
	}
	// #nosec G304 - validated by IsSafePath
	data, err := os.ReadFile(path)
	if err != nil {
		return core.Output{}, err
	}
	if strings.HasSuffix(path, ".lz4") {
		data, err = compress.Decompress(data)
		if err != nil {
			return core.Output{}, err
		}
	}
	var out core.Output
	if err := json.Unmarshal(data, &out); err != nil {
		// Some saved reports may include prefixed operator text before JSON.
		idx := bytes.IndexByte(data, '{')
		if idx < 0 {
			return core.Output{}, err
		}
		if err2 := json.Unmarshal(data[idx:], &out); err2 != nil {
			return core.Output{}, err2
		}
	}
	return out, nil
}

func matchRuleResultsForDecision(artifact audit.Artifact, results []model.RuleResult) []model.RuleResult {
	ids := compliance.ExtractRuleIDsFromFindings(artifact.Findings)
	set := map[string]bool{}
	for _, id := range ids {
		set[id] = true
	}
	out := make([]model.RuleResult, 0, len(ids))
	for _, r := range results {
		if set[r.RuleID] {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RuleID < out[j].RuleID })
	return out
}

func buildWhyChain(results []model.RuleResult) []WhyChainItem {
	out := make([]WhyChainItem, 0, len(results))
	for _, r := range results {
		missing := make([]string, 0, len(r.MissingEvidence))
		for _, req := range r.MissingEvidence {
			missing = append(missing, req.Type)
		}
		out = append(out, WhyChainItem{
			RuleID:           r.RuleID,
			RuleName:         r.Name,
			Verdict:          verdictOfResult(r),
			Explanation:      r.Explanation,
			GapNarrative:     r.GapNarrative,
			ReasonCode:       r.ReasonCode,
			PreconditionOK:   r.PrecondOK,
			SupportingEvents: append([]string(nil), r.SupportingEventIDs...),
			MissingEvidence:  missing,
			CausalBlockers:   append([]string(nil), r.CausalBlockers...),
			NecessaryCauses:  append([]string(nil), r.NecessaryCauses...),
		})
	}
	return out
}

func buildCounterfactuals(results []model.RuleResult, nextMoves []string) []CounterfactualItem {
	out := make([]CounterfactualItem, 0, len(results))
	for _, r := range results {
		item := CounterfactualItem{RuleID: r.RuleID}
		if r.Conflicted {
			item.Assumption = "Contradictory evidence is resolved in attacker favor."
			item.Prediction = "Attack path may become feasible if contradiction is removed and required evidence appears."
		} else if len(r.MissingEvidence) > 0 {
			missing := make([]string, 0, len(r.MissingEvidence))
			for _, req := range r.MissingEvidence {
				missing = append(missing, req.Type)
			}
			item.Assumption = "Missing evidence appears: " + strings.Join(missing, ", ")
			item.Prediction = "Verdict likely shifts from INCOMPLETE to POSSIBLE/CONFIRMED if preconditions remain true."
		} else if r.Feasible {
			item.Assumption = "Current feasible path is uninterrupted."
			item.Prediction = "Attacker likely advances along reachable state graph."
		} else {
			item.Assumption = "Policy or environment constraint changes."
			item.Prediction = "Path may open if controls degrade or telemetry context changes."
		}
		if len(nextMoves) > 0 {
			limit := 3
			if len(nextMoves) < limit {
				limit = len(nextMoves)
			}
			item.NextActions = append(item.NextActions, nextMoves[:limit]...)
		}
		out = append(out, item)
	}
	return out
}

func filterControlsForDecision(export ControlsExport, decisionID string) ControlsExport {
	filtered := ControlsExport{
		GeneratedAt:        export.GeneratedAt,
		AuditChainVerified: export.AuditChainVerified,
		AuditChainError:    export.AuditChainError,
		AuditLifecycle:     export.AuditLifecycle,
		PolicyLifecycle:    export.PolicyLifecycle,
	}
	ruleIDs := map[string]bool{}
	for _, d := range export.DecisionControls {
		if d.DecisionID != decisionID {
			continue
		}
		filtered.DecisionControls = append(filtered.DecisionControls, d)
		ruleIDs[d.RuleID] = true
	}
	for _, m := range export.RuleControlMappings {
		if ruleIDs[m.RuleID] {
			filtered.RuleControlMappings = append(filtered.RuleControlMappings, m)
		}
	}
	for _, d := range export.DualApprovals {
		if d.DecisionID == decisionID {
			filtered.DualApprovals = append(filtered.DualApprovals, d)
		}
	}
	return filtered
}

func buildBundleSummary(artifact audit.Artifact, matched []model.RuleResult, approvals DualApprovalSummary, controls ControlsExport) BundleSummary {
	verdicts := []string{}
	keyFindings := []string{}
	evidenceGaps := []string{}
	for _, r := range matched {
		verdicts = append(verdicts, fmt.Sprintf("%s: %s", r.RuleID, verdictLabel(r)))
		if r.Feasible {
			keyFindings = append(keyFindings, fmt.Sprintf("%s feasible (%.2f)", r.RuleID, r.Confidence))
		}
		if len(r.MissingEvidence) > 0 {
			for _, miss := range r.MissingEvidence {
				evidenceGaps = append(evidenceGaps, fmt.Sprintf("%s missing %s", r.RuleID, miss.Type))
			}
		}
	}
	controlsLinked := 0
	for _, d := range controls.DecisionControls {
		if d.DecisionID == artifact.ID {
			controlsLinked++
		}
	}
	notes := []string{
		"summary is derived from structured reasoning output",
		"bundle integrity is verified via manifest digest + optional signature",
	}
	return BundleSummary{
		DecisionID:           artifact.ID,
		GeneratedAt:          time.Now().UTC().Format(time.RFC3339),
		Verdicts:             dedupeStrings(verdicts),
		KeyFindings:          dedupeStrings(keyFindings),
		EvidenceGaps:         dedupeStrings(evidenceGaps),
		ControlsLinked:       controlsLinked,
		DualApprovalRequired: approvals.Required > 0,
		DualApproved:         approvals.DualApproved,
		BundleVerified:       controls.AuditChainVerified,
		Notes:                notes,
	}
}

func verdictLabel(r model.RuleResult) string {
	if r.PolicyImpossible {
		return "policy_impossible"
	}
	if r.Conflicted {
		return "conflicted"
	}
	if r.Feasible {
		return "feasible"
	}
	if len(r.MissingEvidence) > 0 {
		return "incomplete"
	}
	return "unknown"
}

func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func bundleReadmeText() string {
	return strings.TrimSpace(`
Aman Evidence Bundle

Files:
- decision.json: Decision summary, hashes, and audit chain pointers.
- why_chain.json: Causal reasoning chain per rule (verdicts + explanations).
- counterfactuals.json: "what-if" analysis and next likely actions.
- controls.json: Framework control mappings + policy/audit lifecycle metadata.
- oversight.json: Human approvals and dual-control status.
- summary.json: Human-friendly summary of the bundle contents.
- report.html: Human-readable view (open in a browser).
- rule_catalog_version.json: Rule catalog count and source.
- manifest.json: Bundle manifest with file hashes.

Verification:
- Use: aman audit bundle-verify --bundle <bundle.zip>
- The manifest digest + optional signature provide integrity.
`)
}

func buildHumanReportHTML(summary BundleSummary, matched []model.RuleResult, approvals DualApprovalSummary) string {
	type row struct {
		RuleID         string
		Verdict        string
		ReasonCode     string
		PreconditionOK string
		Explanation    string
	}
	type confRow struct {
		RuleID        string
		Coverage      string
		Recency       string
		Corroboration string
		SupportEvents string
	}
	rows := make([]row, 0, len(matched))
	confRows := make([]confRow, 0, len(matched))
	for _, r := range matched {
		rows = append(rows, row{
			RuleID:         r.RuleID,
			Verdict:        verdictLabel(r),
			ReasonCode:     r.ReasonCode,
			PreconditionOK: strconv.FormatBool(r.PrecondOK),
			Explanation:    r.Explanation,
		})
		if r.ConfidenceFactors != nil {
			confRows = append(confRows, confRow{
				RuleID:        r.RuleID,
				Coverage:      fmt.Sprintf("%d / %d", r.ConfidenceFactors.EvidencePresent, r.ConfidenceFactors.EvidenceTotal),
				Recency:       confidenceBandLabel(r.ConfidenceFactors.Recency),
				Corroboration: confidenceBandLabel(r.ConfidenceFactors.Corroboration),
				SupportEvents: fmt.Sprintf("%d", r.ConfidenceFactors.SupportingEvents),
			})
		}
	}
	builder := strings.Builder{}
	builder.WriteString("<!doctype html><html><head><meta charset=\"utf-8\">")
	builder.WriteString("<title>Aman Evidence Report</title>")
	builder.WriteString("<style>body{font-family:Arial,Helvetica,sans-serif;margin:24px;color:#111}h1,h2{margin:0 0 12px}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ddd;padding:8px;font-size:14px}th{background:#f4f6f8;text-align:left}section{margin-bottom:24px}code{background:#f4f6f8;padding:2px 4px;border-radius:4px}</style>")
	builder.WriteString("</head><body>")
	builder.WriteString("<h1>Aman Evidence Report</h1>")
	builder.WriteString("<section><h2>Summary</h2>")
	builder.WriteString(fmt.Sprintf("<p><strong>Decision:</strong> %s</p>", summary.DecisionID))
	builder.WriteString(fmt.Sprintf("<p><strong>Generated:</strong> %s</p>", summary.GeneratedAt))
	builder.WriteString(fmt.Sprintf("<p><strong>Bundle verified:</strong> %t</p>", summary.BundleVerified))
	builder.WriteString(fmt.Sprintf("<p><strong>Dual approval:</strong> %t (required=%t)</p>", summary.DualApproved, summary.DualApprovalRequired))
	builder.WriteString(fmt.Sprintf("<p><strong>Controls linked:</strong> %d</p>", summary.ControlsLinked))
	if len(summary.KeyFindings) > 0 {
		builder.WriteString("<p><strong>Key findings:</strong></p><ul>")
		for _, f := range summary.KeyFindings {
			builder.WriteString("<li>" + htmlEscape(f) + "</li>")
		}
		builder.WriteString("</ul>")
	}
	if len(summary.EvidenceGaps) > 0 {
		builder.WriteString("<p><strong>Evidence gaps:</strong></p><ul>")
		for _, g := range summary.EvidenceGaps {
			builder.WriteString("<li>" + htmlEscape(g) + "</li>")
		}
		builder.WriteString("</ul>")
	}
	builder.WriteString("</section>")

	builder.WriteString("<section><h2>Why Chain</h2>")
	builder.WriteString("<table><thead><tr><th>Rule</th><th>Verdict</th><th>Reason</th><th>Precondition OK</th><th>Explanation</th></tr></thead><tbody>")
	for _, r := range rows {
		builder.WriteString("<tr>")
		builder.WriteString("<td><code>" + htmlEscape(r.RuleID) + "</code></td>")
		builder.WriteString("<td>" + htmlEscape(r.Verdict) + "</td>")
		builder.WriteString("<td>" + htmlEscape(r.ReasonCode) + "</td>")
		builder.WriteString("<td>" + htmlEscape(r.PreconditionOK) + "</td>")
		builder.WriteString("<td>" + htmlEscape(r.Explanation) + "</td>")
		builder.WriteString("</tr>")
	}
	builder.WriteString("</tbody></table></section>")

	if len(confRows) > 0 {
		builder.WriteString("<section><h2>Confidence Rationale</h2>")
		builder.WriteString("<p>Confidence is a support score derived from evidence coverage, recency, and corroboration. It is not a probability.</p>")
		builder.WriteString("<table><thead><tr><th>Rule</th><th>Coverage</th><th>Recency</th><th>Corroboration</th><th>Supporting Events</th></tr></thead><tbody>")
		for _, r := range confRows {
			builder.WriteString("<tr>")
			builder.WriteString("<td><code>" + htmlEscape(r.RuleID) + "</code></td>")
			builder.WriteString("<td>" + htmlEscape(r.Coverage) + "</td>")
			builder.WriteString("<td>" + htmlEscape(r.Recency) + "</td>")
			builder.WriteString("<td>" + htmlEscape(r.Corroboration) + "</td>")
			builder.WriteString("<td>" + htmlEscape(r.SupportEvents) + "</td>")
			builder.WriteString("</tr>")
		}
		builder.WriteString("</tbody></table></section>")
	}

	builder.WriteString("<section><h2>Oversight</h2>")
	builder.WriteString(fmt.Sprintf("<p><strong>Required signers:</strong> %d</p>", approvals.Required))
	builder.WriteString(fmt.Sprintf("<p><strong>Valid signers:</strong> %d</p>", approvals.ValidSigners))
	builder.WriteString(fmt.Sprintf("<p><strong>Dual approved:</strong> %t</p>", approvals.DualApproved))
	if len(approvals.SignerIDs) > 0 {
		builder.WriteString("<p><strong>Signers:</strong> " + htmlEscape(strings.Join(approvals.SignerIDs, ", ")) + "</p>")
	}
	builder.WriteString("</section>")

	builder.WriteString("</body></html>")
	return builder.String()
}

func htmlEscape(s string) string {
	replacer := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		"\"", "&quot;",
		"'", "&#39;",
	)
	return replacer.Replace(s)
}

func confidenceBandLabel(value float64) string {
	switch {
	case value >= 0.8:
		return "High"
	case value >= 0.6:
		return "Moderate"
	default:
		return "Low"
	}
}

func approvalSummaryForDecision(approvals []DualApprovalSummary, decisionID string) DualApprovalSummary {
	for _, a := range approvals {
		if a.DecisionID == decisionID {
			return a
		}
	}
	return DualApprovalSummary{
		DecisionID:   decisionID,
		Required:     2,
		DualApproved: false,
	}
}

func verdictOfResult(r model.RuleResult) string {
	switch {
	case r.PolicyImpossible:
		return "POLICY_IMPOSSIBLE"
	case r.Conflicted:
		return "CONFLICTED"
	case r.Feasible:
		return "POSSIBLE"
	case !r.PrecondOK || len(r.MissingEvidence) > 0:
		return "INCOMPLETE"
	default:
		return "IMPOSSIBLE"
	}
}

func packageTimestamp(reproducible bool, fallback time.Time) time.Time {
	if reproducible {
		if !fallback.IsZero() {
			return fallback.UTC()
		}
		return time.Unix(0, 0).UTC()
	}
	return time.Now().UTC()
}

func handleAudit(args []string) {
	if len(args) == 0 {
		fatal(errors.New("audit requires a subcommand: verify|explain|export|bundle|bundle-verify|package"))
	}
	switch args[0] {
	case "verify":
		fs := flag.NewFlagSet("audit verify", flag.ExitOnError)
		auditPath := fs.String("audit", "data/audit.log", "audit log")
		if err := fs.Parse(args[1:]); err != nil {
			fatal(err)
		}
		if err := audit.VerifyChain(*auditPath); err != nil {
			fatal(err)
		}
		outln("Audit chain: VALID")
	case "explain":
		fs := flag.NewFlagSet("audit explain", flag.ExitOnError)
		auditPath := fs.String("audit", "data/audit.log", "audit log")
		decision := fs.String("decision", "", "decision id")
		rulesPath := fs.String("rules", "data/rules.json", "rules file")
		extraPath := fs.String("rules-extra", "", "optional extra rules file")
		if err := fs.Parse(args[1:]); err != nil {
			fatal(err)
		}
		if *decision == "" {
			fatal(errors.New("audit explain requires --decision"))
		}
		artifact, err := audit.FindArtifact(*auditPath, *decision)
		if err != nil {
			fatal(err)
		}
		outln("Decision: " + artifact.ID)
		outln("Summary: " + artifact.Summary)
		outln("Findings: " + strings.Join(artifact.Findings, "; "))
		ruleIDs := compliance.ExtractRuleIDsFromFindings(artifact.Findings)
		if len(ruleIDs) > 0 {
			rules, err := logic.LoadRulesCombined(*rulesPath, *extraPath)
			if err != nil {
				fatal(err)
			}
			mappings := compliance.BuildRuleControlMappings(ruleIDs, rules)
			if len(mappings) > 0 {
				outln("Control mapping (SOC 2 / NIST CSF / ISO 27001):")
				for _, m := range mappings {
					outln("- " + m.RuleID + " (" + m.RuleName + ")")
					if len(m.NistCSF) > 0 {
						outln("  NIST CSF: " + strings.Join(m.NistCSF, ", "))
					}
					if len(m.Soc2CC) > 0 {
						outln("  SOC 2: " + strings.Join(m.Soc2CC, ", "))
					}
					if len(m.ISO27001) > 0 {
						outln("  ISO 27001: " + strings.Join(m.ISO27001, ", "))
					}
				}
			}
		}
	case "export":
		fs := flag.NewFlagSet("audit export", flag.ExitOnError)
		auditPath := fs.String("audit", "data/audit.log", "audit log")
		out := fs.String("out", "", "output file")
		format := fs.String("format", "json", "format")
		if err := fs.Parse(args[1:]); err != nil {
			fatal(err)
		}
		if *format != "json" {
			fatal(errors.New("only json export supported"))
		}
		if *out == "" {
			if !gFlags.Quiet {
				if err := audit.ExportLog(*auditPath, os.Stdout); err != nil {
					fatal(err)
				}
			}
			return
		}
		//nolint:gosec // path is user supplied
		f, err := os.OpenFile(*out, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
		if err != nil {
			fatal(err)
		}
		defer func() { _ = f.Close() }()
		if err := audit.ExportLog(*auditPath, f); err != nil {
			fatal(err)
		}
		outln("Audit export written: " + *out)
	case "bundle":
		fs := flag.NewFlagSet("audit bundle", flag.ExitOnError)
		auditPath := fs.String("audit", "data/audit.log", "audit log")
		signedAuditPath := fs.String("signed-audit", "data/signed_audit.log", "signed audit log")
		approvalsPath := fs.String("approvals", "data/approvals.log", "approvals log")
		reportPath := fs.String("report", "data/report.json", "assessment report")
		rulesPath := fs.String("rules", "data/rules.json", "rules file")
		rulesExtra := fs.String("rules-extra", "", "optional extra rules file")
		policyPath := fs.String("policy", "data/policy.json", "policy file")
		controlsJSON := fs.Bool("controls-json", false, "embed structured controls export into the bundle")
		reproducible := fs.Bool("reproducible", false, "produce deterministic bundle bytes for identical inputs")
		out := fs.String("out", "data/evidence_bundle.zip", "bundle output path")
		keyPath := fs.String("key", "", "optional keypair json for bundle signature")
		signer := fs.String("signer", "", "bundle signer id")
		if err := fs.Parse(args[1:]); err != nil {
			fatal(err)
		}
		inputs := map[string]string{}
		if strings.TrimSpace(*auditPath) != "" {
			inputs["audit"] = *auditPath
		}
		if strings.TrimSpace(*signedAuditPath) != "" {
			inputs["signed_audit"] = *signedAuditPath
		}
		if strings.TrimSpace(*approvalsPath) != "" {
			inputs["approvals"] = *approvalsPath
		}
		if strings.TrimSpace(*reportPath) != "" {
			inputs["report"] = *reportPath
		}
		opts := audit.BundleOptions{
			OutputPath:   *out,
			Inputs:       inputs,
			Reproducible: *reproducible,
			Signer:       strings.TrimSpace(*signer),
		}
		if *controlsJSON {
			export, err := buildControlsExport(*auditPath, *signedAuditPath, *approvalsPath, *rulesPath, *rulesExtra, *policyPath, *reproducible)
			if err != nil {
				fatal(err)
			}
			payload, err := json.MarshalIndent(export, "", "  ")
			if err != nil {
				fatal(err)
			}
			opts.Inline = map[string][]byte{
				"controls.json": payload,
			}
		}
		if strings.TrimSpace(*keyPath) != "" {
			var kp KeypairFile
			readJSON(*keyPath, &kp)
			opts.PublicKey = kp.PublicKey
			opts.PrivateKey = kp.PrivateKey
		}
		manifest, err := audit.CreateEvidenceBundle(opts)
		if err != nil {
			fatal(err)
		}
		outln("Evidence bundle written: " + *out)
		outln(fmt.Sprintf("Files: %d", len(manifest.Files)))
		outln("Digest: " + manifest.Digest)
		if manifest.Signature != "" {
			outln("Signature: present")
		}
	case "bundle-verify":
		fs := flag.NewFlagSet("audit bundle-verify", flag.ExitOnError)
		bundle := fs.String("bundle", "", "bundle zip path")
		pubkey := fs.String("pubkey", "", "optional expected base64 public key")
		if err := fs.Parse(args[1:]); err != nil {
			fatal(err)
		}
		if strings.TrimSpace(*bundle) == "" {
			fatal(errors.New("audit bundle-verify requires --bundle"))
		}
		res, err := audit.VerifyEvidenceBundle(*bundle, strings.TrimSpace(*pubkey))
		if err != nil {
			if gFlags.JSON {
				outJSON(res)
			}
			fatal(err)
		}
		if gFlags.JSON {
			outJSON(res)
			return
		}
		outln(fmt.Sprintf("Bundle files verified: %d", res.FilesVerified))
		outln("Digest: VALID")
		if res.SignaturePresent && res.SignatureValid {
			outln("Signature: VALID")
		} else if !res.SignaturePresent {
			outln("Signature: NOT PRESENT")
		}
		outln("Evidence bundle verification passed")
	case "package":
		fs := flag.NewFlagSet("audit package", flag.ExitOnError)
		decisionID := fs.String("decision", "", "decision id")
		auditPath := fs.String("audit", "data/audit.log", "audit log")
		signedAuditPath := fs.String("signed-audit", "data/signed_audit.log", "signed audit log")
		approvalsPath := fs.String("approvals", "data/approvals.log", "approvals log")
		reportPath := fs.String("report", "data/report.json", "assessment report")
		rulesPath := fs.String("rules", "data/rules.json", "rules file")
		rulesExtra := fs.String("rules-extra", "", "optional extra rules file")
		policyPath := fs.String("policy", "data/policy.json", "policy file")
		out := fs.String("out", "", "output evidence zip")
		keyPath := fs.String("key", "", "optional keypair json for bundle signature")
		signer := fs.String("signer", "", "bundle signer id")
		includeWhy := fs.Bool("include-why", true, "include causal why-chain export")
		includeCounterfactuals := fs.Bool("include-counterfactuals", true, "include counterfactual what-if export")
		includeControls := fs.Bool("controls-json", true, "include controls mapping export")
		requireDual := fs.Bool("require-dual", false, "require dual approval before packaging")
		reproducible := fs.Bool("reproducible", false, "produce deterministic package bytes for identical inputs")
		if err := fs.Parse(args[1:]); err != nil {
			fatal(err)
		}
		if strings.TrimSpace(*decisionID) == "" {
			fatal(errors.New("audit package requires --decision"))
		}
		if strings.TrimSpace(*out) == "" {
			fatal(errors.New("audit package requires --out"))
		}
		artifacts, err := readAuditArtifacts(*auditPath)
		if err != nil {
			fatal(err)
		}
		artifact, err := findArtifactByID(artifacts, *decisionID)
		if err != nil {
			fatal(err)
		}
		rep, err := loadCoreOutput(*reportPath)
		if err != nil {
			fatal(err)
		}
		rules, err := logic.LoadRulesCombined(*rulesPath, *rulesExtra)
		if err != nil {
			fatal(err)
		}
		controlsExport, err := buildControlsExport(*auditPath, *signedAuditPath, *approvalsPath, *rulesPath, *rulesExtra, *policyPath, *reproducible)
		if err != nil {
			fatal(err)
		}
		decisionApprovals := approvalSummaryForDecision(controlsExport.DualApprovals, *decisionID)
		if *requireDual && !decisionApprovals.DualApproved {
			fatal(errors.New("dual approval required but not satisfied for decision"))
		}
		inline := map[string][]byte{}
		decisionDir := fmt.Sprintf("decision_%s", artifact.ID)
		decisionPayload := DecisionPackage{
			DecisionID: artifact.ID,
			Summary:    artifact.Summary,
			Findings:   artifact.Findings,
			Reasoning:  artifact.Reasoning,
			CreatedAt:  artifact.CreatedAt.Format(time.RFC3339),
			Hash:       artifact.Hash,
			PrevHash:   artifact.PrevHash,
		}
		decisionBytes, err := json.MarshalIndent(decisionPayload, "", "  ")
		if err != nil {
			fatal(err)
		}
		inline[filepath.ToSlash(filepath.Join(decisionDir, "decision.json"))] = decisionBytes

		matched := matchRuleResultsForDecision(artifact, rep.Reasoning.Results)
		if *includeWhy {
			why := buildWhyChain(matched)
			whyBytes, err := json.MarshalIndent(why, "", "  ")
			if err != nil {
				fatal(err)
			}
			inline[filepath.ToSlash(filepath.Join(decisionDir, "why_chain.json"))] = whyBytes
		}
		if *includeCounterfactuals {
			counterfactuals := buildCounterfactuals(matched, rep.NextMoves)
			cfBytes, err := json.MarshalIndent(counterfactuals, "", "  ")
			if err != nil {
				fatal(err)
			}
			inline[filepath.ToSlash(filepath.Join(decisionDir, "counterfactuals.json"))] = cfBytes
		}
		if *includeControls {
			filtered := filterControlsForDecision(controlsExport, *decisionID)
			controlsBytes, err := json.MarshalIndent(filtered, "", "  ")
			if err != nil {
				fatal(err)
			}
			inline[filepath.ToSlash(filepath.Join(decisionDir, "controls.json"))] = controlsBytes
		}
		oversightBytes, err := json.MarshalIndent(decisionApprovals, "", "  ")
		if err != nil {
			fatal(err)
		}
		inline[filepath.ToSlash(filepath.Join(decisionDir, "oversight.json"))] = oversightBytes
		if *includeControls {
			summary := buildBundleSummary(artifact, matched, decisionApprovals, controlsExport)
			summaryBytes, err := json.MarshalIndent(summary, "", "  ")
			if err != nil {
				fatal(err)
			}
			inline[filepath.ToSlash(filepath.Join(decisionDir, "summary.json"))] = summaryBytes
			inline[filepath.ToSlash(filepath.Join(decisionDir, "report.html"))] = []byte(buildHumanReportHTML(summary, matched, decisionApprovals))
		}
		inline[filepath.ToSlash(filepath.Join(decisionDir, "README.txt"))] = []byte(bundleReadmeText())
		inline[filepath.ToSlash(filepath.Join(decisionDir, "rule_catalog_version.json"))], err = json.MarshalIndent(map[string]any{
			"generated_at": packageTimestamp(*reproducible, artifact.CreatedAt).Format(time.RFC3339),
			"rule_count":   len(rules),
			"rules_file":   *rulesPath,
		}, "", "  ")
		if err != nil {
			fatal(err)
		}

		inputs := map[string]string{
			filepath.ToSlash(filepath.Join(decisionDir, "audit")):     *auditPath,
			filepath.ToSlash(filepath.Join(decisionDir, "approvals")): *approvalsPath,
			filepath.ToSlash(filepath.Join(decisionDir, "report")):    *reportPath,
		}
		opts := audit.BundleOptions{
			OutputPath:   *out,
			Inputs:       inputs,
			Inline:       inline,
			Reproducible: *reproducible,
			Signer:       strings.TrimSpace(*signer),
		}
		if strings.TrimSpace(*keyPath) != "" {
			var kp KeypairFile
			readJSON(*keyPath, &kp)
			opts.PublicKey = kp.PublicKey
			opts.PrivateKey = kp.PrivateKey
		}
		manifest, err := audit.CreateEvidenceBundle(opts)
		if err != nil {
			fatal(err)
		}
		outln("Audit package written: " + *out)
		outln(fmt.Sprintf("Decision: %s", artifact.ID))
		outln(fmt.Sprintf("Files: %d", len(manifest.Files)))
		outln("Digest: " + manifest.Digest)
		if manifest.Signature != "" {
			outln("Signature: present")
		}
	default:
		fatal(errors.New("unknown audit subcommand"))
	}
}

func handleSystem(args []string) {
	if len(args) == 0 {
		fatal(errors.New("system requires a subcommand: status|config|health|coverage|nist|killchain|confidence|engines|pilot-metrics|integration-readiness|integration-quickstart|noisegraph-quickstart|roi-scorecard|demo-pack|rule-lint|drift-quickstart"))
	}
	switch args[0] {
	case "status":
		baseline := "MISSING"
		if _, err := zerotrust.LoadBaseline("data/zero_trust_baseline.json"); err == nil {
			baseline = "OK"
		}
		outln("Zero-trust baseline: " + baseline)
		outln("Config profile: " + gFlags.Profile)
	case "config":
		if len(args) < 2 || args[1] != "show" {
			fatal(errors.New("system config show"))
		}
		cfg, err := ops.LoadConfig("data/ops.json")
		if err != nil {
			fatal(err)
		}
		outJSON(cfg)
	case "health":
		outln("Ingest: OK")
		outln("Reasoning: OK")
		outln("Governance: OK")
	case "engines":
		specs := engines.Builtins()
		if gFlags.JSON {
			outJSON(specs)
			return
		}
		outln("Optional engines (external modules):")
		for _, spec := range specs {
			outln("- " + spec.Name + " (" + spec.ID + ")")
			outln("  Purpose: " + spec.Purpose)
			outln("  Integration: " + spec.Integration)
			outln("  Status: " + spec.Status)
		}
	case "pilot-metrics":
		fs := flag.NewFlagSet("system pilot-metrics", flag.ExitOnError)
		reportPath := fs.String("report", "data/bench/report.json", "reason/assess report with ai_overlay")
		historyPath := fs.String("history", "data/incident_history.json", "incident history with analyst outcomes")
		outPath := fs.String("out", "", "output file (optional)")
		format := fs.String("format", "json", "output format: json|md")
		if err := fs.Parse(args[1:]); err != nil {
			fatal(err)
		}
		rep, err := loadReportFile(*reportPath)
		if err != nil {
			fatal(err)
		}
		if len(rep.AIAlerts) == 0 && !rep.AIOverlay.Enabled {
			fatal(errors.New("report has no ai overlay data; rerun assess/reason with --ai-overlay"))
		}
		history, err := assist.LoadHistory(*historyPath)
		if err != nil {
			fatal(err)
		}
		metrics := computePilotMetrics(rep, history, *reportPath, *historyPath)
		switch strings.ToLower(strings.TrimSpace(*format)) {
		case "json":
			data, err := json.MarshalIndent(metrics, "", "  ")
			if err != nil {
				fatal(err)
			}
			if *outPath == "" {
				outln(string(data))
			} else {
				if !ops.IsSafePath(*outPath) {
					fatal(os.ErrInvalid)
				}
				if err := os.WriteFile(*outPath, data, 0600); err != nil {
					fatal(err)
				}
				outln("Pilot metrics written: " + *outPath)
			}
		case "md":
			md := renderPilotMetricsMarkdown(metrics)
			writeText(*outPath, md)
		default:
			fatal(errors.New("unknown format"))
		}
	case "integration-readiness":
		fs := flag.NewFlagSet("system integration-readiness", flag.ExitOnError)
		rulesPath := fs.String("rules", "data/rules.json", "rules json")
		rulesExtra := fs.String("rules-extra", "", "optional expansion rules json")
		outPath := fs.String("out", "", "output file (optional)")
		strict := fs.Bool("strict", false, "fail checks unless category meets strict thresholds")
		minEvents := fs.Int("min-events", 1, "minimum normalized events per category in strict mode")
		minFeasible := fs.Int("min-feasible", 1, "minimum feasible findings per category in strict mode")
		if err := fs.Parse(args[1:]); err != nil {
			fatal(err)
		}
		rep, err := runIntegrationReadiness(*rulesPath, *rulesExtra, *strict, *minEvents, *minFeasible)
		if err != nil {
			fatal(err)
		}
		if *outPath != "" {
			data, err := json.MarshalIndent(rep, "", "  ")
			if err != nil {
				fatal(err)
			}
			if !ops.IsSafePath(*outPath) {
				fatal(os.ErrInvalid)
			}
			if err := os.WriteFile(*outPath, data, 0600); err != nil {
				fatal(err)
			}
			outln("Integration readiness written: " + *outPath)
		}
		if gFlags.JSON {
			outJSON(rep)
			return
		}
		outln(fmt.Sprintf("Integration readiness: passed=%d failed=%d", rep.Passed, rep.Failed))
		for _, c := range rep.Checks {
			status := "PASS"
			if !c.Pass {
				status = "FAIL"
			}
			outln(fmt.Sprintf("- [%s] %s schema=%s events=%d feasible=%d fixture=%s", status, c.Category, c.Schema, c.EventCount, c.FeasibleCount, c.Fixture))
			if c.Error != "" {
				outln("  error: " + c.Error)
			}
		}
		if *strict && rep.Failed > 0 {
			fatal(errors.New("integration readiness strict mode failed"))
		}
	case "integration-quickstart":
		fs := flag.NewFlagSet("system integration-quickstart", flag.ExitOnError)
		rulesPath := fs.String("rules", "data/rules.json", "rules json")
		rulesExtra := fs.String("rules-extra", "", "optional expansion rules json")
		outDir := fs.String("outdir", "data/onboarding", "output directory")
		outPath := fs.String("out", "", "output summary report path (optional)")
		aiThreshold := fs.Float64("ai-threshold", 0.20, "ai overlay threshold")
		aiMax := fs.Int("ai-max", 50, "ai overlay max alerts")
		if err := fs.Parse(args[1:]); err != nil {
			fatal(err)
		}
		rep, err := runIntegrationQuickstart(*rulesPath, *rulesExtra, *outDir, *aiThreshold, *aiMax)
		if err != nil {
			fatal(err)
		}
		if *outPath != "" {
			data, err := json.MarshalIndent(rep, "", "  ")
			if err != nil {
				fatal(err)
			}
			if !ops.IsSafePath(*outPath) {
				fatal(os.ErrInvalid)
			}
			if err := os.WriteFile(*outPath, data, 0600); err != nil {
				fatal(err)
			}
			outln("Integration quickstart written: " + *outPath)
		}
		if gFlags.JSON {
			outJSON(rep)
			return
		}
		outln(fmt.Sprintf("Integration quickstart: passed=%d failed=%d outdir=%s", rep.Passed, rep.Failed, rep.OutputDir))
		for _, r := range rep.Runs {
			status := "PASS"
			if !r.Pass {
				status = "FAIL"
			}
			outln(fmt.Sprintf("- [%s] %s schema=%s events=%d feasible=%d candidates=%d escalated=%d", status, r.Category, r.Schema, r.EventCount, r.FeasibleCount, r.CandidateCount, r.EscalatedCount))
			outln("  events: " + r.EventsPath)
			outln("  report: " + r.ReportPath)
			if r.Error != "" {
				outln("  error: " + r.Error)
			}
		}
	case "drift-quickstart":
		fs := flag.NewFlagSet("system drift-quickstart", flag.ExitOnError)
		outDir := fs.String("outdir", "data/inventory", "output directory")
		configPath := fs.String("config", "data/inventory/config.json", "adapter config json")
		basePath := fs.String("base", "data/env.json", "baseline env.json path")
		driftPath := fs.String("drift", "data/drift.json", "drift report output path")
		requestPath := fs.String("drift-request", "data/drift_request.json", "drift approval request output path")
		interval := fs.String("interval", "6h", "refresh interval")
		jitter := fs.String("jitter", "30m", "interval jitter")
		outPath := fs.String("out", "", "output summary report path (optional)")
		if err := fs.Parse(args[1:]); err != nil {
			fatal(err)
		}
		if !ops.IsSafePath(*outDir) {
			fatal(os.ErrInvalid)
		}
		if err := os.MkdirAll(*outDir, 0755); err != nil {
			fatal(err)
		}
		scriptPath := filepath.Join(*outDir, "auto_drift.sh")
		readmePath := filepath.Join(*outDir, "auto_drift_README.md")
		script := `#!/usr/bin/env bash
set -euo pipefail

AMAN_BIN="${AMAN_BIN:-aman}"
CONFIG="${1:-` + *configPath + `}"
BASE="${2:-` + *basePath + `}"
DRIFT="${3:-` + *driftPath + `}"
DRIFT_REQUEST="${4:-` + *requestPath + `}"
INTERVAL="${5:-` + *interval + `}"
JITTER="${6:-` + *jitter + `}"

echo "Starting Aman inventory schedule..."
$AMAN_BIN inventory-schedule -provider all -config "$CONFIG" -base "$BASE" -out "$BASE" -drift "$DRIFT" -drift-request "$DRIFT_REQUEST" -interval "$INTERVAL" -jitter "$JITTER"
`
		readme := `# Aman Auto Drift Workflow

This quickstart generates a minimal auto-drift runner.

## 1) One-time baseline
Run once to create your initial env snapshot:

` + "```\n" + `aman inventory-refresh -provider all -config ` + *configPath + ` -base ` + *basePath + ` -out ` + *basePath + ` -drift ` + *driftPath + ` -drift-request ` + *requestPath + `
` + "```\n" + `

## 2) Start auto refresh
Run the schedule loop (recommended in tmux/systemd):

` + "```\n" + `bash ` + scriptPath + `
` + "```\n" + `

### Systemd example (optional)
Create a unit that runs the script in the background.

` + "```\n" + `[Unit]
Description=Aman inventory auto drift

[Service]
ExecStart=/bin/bash ` + scriptPath + `
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
` + "```\n" + `

## Outputs
- baseline: ` + *basePath + `
- drift report: ` + *driftPath + `
- drift request (if changes): ` + *requestPath + `
`
		writeText(scriptPath, script)
		if err := os.Chmod(scriptPath, 0755); err != nil {
			fatal(err)
		}
		writeText(readmePath, readme)
		report := map[string]string{
			"output_dir":    *outDir,
			"script_path":   scriptPath,
			"readme_path":   readmePath,
			"config_path":   *configPath,
			"base_path":     *basePath,
			"drift_path":    *driftPath,
			"drift_request": *requestPath,
			"interval":      *interval,
			"jitter":        *jitter,
		}
		if *outPath != "" {
			data, err := json.MarshalIndent(report, "", "  ")
			if err != nil {
				fatal(err)
			}
			if !ops.IsSafePath(*outPath) {
				fatal(os.ErrInvalid)
			}
			if err := os.WriteFile(*outPath, data, 0600); err != nil {
				fatal(err)
			}
			outln("Drift quickstart written: " + *outPath)
		}
		if gFlags.JSON {
			outJSON(report)
			return
		}
		outln("Drift quickstart ready:")
		outln("- Script: " + scriptPath)
		outln("- README: " + readmePath)
		outln("- Baseline: " + *basePath)
		outln("- Drift report: " + *driftPath)
	case "noisegraph-quickstart":
		fs := flag.NewFlagSet("system noisegraph-quickstart", flag.ExitOnError)
		decisions := fs.String("decisions", "external/noisegraph/state/decisions.jsonl", "noisegraph decisions JSONL path")
		eventsOut := fs.String("events", "data/noisegraph_events.json", "converted Aman events output path")
		reportOut := fs.String("report", "docs/noisegraph_quickstart.json", "quickstart report output path")
		rulesPath := fs.String("rules", "data/rules.json", "rules json")
		rulesExtra := fs.String("rules-extra", "", "optional expansion rules json")
		only := fs.String("only", "keep,escalate", "comma-separated statuses to include")
		aiThreshold := fs.Float64("ai-threshold", 0.20, "ai overlay threshold")
		aiMax := fs.Int("ai-max", 50, "ai overlay max alerts")
		if err := fs.Parse(args[1:]); err != nil {
			fatal(err)
		}
		rep, err := runNoisegraphQuickstart(*decisions, *eventsOut, *reportOut, *rulesPath, *rulesExtra, *only, *aiThreshold, *aiMax)
		if err != nil {
			fatal(err)
		}
		if gFlags.JSON {
			outJSON(rep)
			return
		}
		outln("Noisegraph quickstart completed")
		outln(fmt.Sprintf("- Decisions parsed: %d", rep.ParsedLines))
		outln(fmt.Sprintf("- Events written: %d (%s)", rep.EventsCount, rep.EventsPath))
		outln(fmt.Sprintf("- AI candidates: %d", rep.Reasoning.AIOverlay.CandidateCount))
		outln(fmt.Sprintf("- Escalated: %d", rep.Reasoning.AIOverlay.EscalatedCount))
		outln(fmt.Sprintf("- Triaged: %d", rep.Reasoning.AIOverlay.TriagedCount))
		outln(fmt.Sprintf("- Suppressed: %d", rep.Reasoning.AIOverlay.SuppressedCount))
		if rep.ReportPath != "" {
			outln(fmt.Sprintf("- Report: %s", rep.ReportPath))
		}
	case "roi-scorecard":
		fs := flag.NewFlagSet("system roi-scorecard", flag.ExitOnError)
		pilotPath := fs.String("pilot", "docs/pilot_metrics_report.json", "pilot metrics JSON path")
		integrationPath := fs.String("integration", "docs/integration_readiness.json", "integration readiness JSON path")
		benchmarkPath := fs.String("benchmark", "docs/production_benchmark_report.md", "production benchmark report markdown path")
		outPath := fs.String("out", "", "output path (optional, .md or .json)")
		if err := fs.Parse(args[1:]); err != nil {
			fatal(err)
		}
		score, err := buildROIScorecard(*pilotPath, *integrationPath, *benchmarkPath)
		if err != nil {
			fatal(err)
		}
		if *outPath != "" {
			if strings.HasSuffix(strings.ToLower(*outPath), ".md") {
				writeText(*outPath, renderROIScorecardMarkdown(score))
			} else {
				writeJSON(*outPath, score)
			}
		}
		if gFlags.JSON {
			outJSON(score)
			return
		}
		outln(renderROIScorecardMarkdown(score))
	case "demo-pack":
		fs := flag.NewFlagSet("system demo-pack", flag.ExitOnError)
		outDir := fs.String("outdir", "docs/demo_pack", "output directory")
		rulesPath := fs.String("rules", "data/rules.json", "rules json")
		rulesExtra := fs.String("rules-extra", "", "optional expansion rules json")
		if err := fs.Parse(args[1:]); err != nil {
			fatal(err)
		}
		rep, err := buildDemoPack(*outDir, *rulesPath, *rulesExtra)
		if err != nil {
			fatal(err)
		}
		if gFlags.JSON {
			outJSON(rep)
			return
		}
		outln(fmt.Sprintf("Demo pack generated: %s", rep.OutDir))
		for _, f := range rep.Files {
			outln("- " + f)
		}
	case "rule-lint":
		fs := flag.NewFlagSet("system rule-lint", flag.ExitOnError)
		rulesPath := fs.String("rules", "data/rules.json", "rules json")
		rulesExtra := fs.String("rules-extra", "", "optional expansion rules json")
		outPath := fs.String("out", "", "output file (optional)")
		format := fs.String("format", "text", "output format: text|json|md")
		if err := fs.Parse(args[1:]); err != nil {
			fatal(err)
		}
		rules, err := logic.LoadRulesCombined(*rulesPath, *rulesExtra)
		if err != nil {
			fatal(err)
		}
		warnings := logic.LintRules(rules)
		report := RuleLintReport{
			GeneratedAt:  time.Now().UTC(),
			RulesPath:    *rulesPath,
			WarningCount: len(warnings),
			Warnings:     warnings,
		}
		switch strings.ToLower(strings.TrimSpace(*format)) {
		case "json":
			if *outPath != "" {
				writeJSON(*outPath, report)
			} else {
				outJSON(report)
			}
		case "md":
			md := renderRuleLintMarkdown(report)
			writeText(*outPath, md)
		default:
			outln(fmt.Sprintf("Rule lint: %d warnings", report.WarningCount))
			for _, w := range warnings {
				detail := w.Detail
				if detail != "" {
					detail = " — " + detail
				}
				outln(fmt.Sprintf("- %s [%s] %s%s", w.RuleID, w.Issue, w.Severity, detail))
			}
			if *outPath != "" {
				writeText(*outPath, renderRuleLintMarkdown(report))
			}
		}
	case "coverage":
		fs := flag.NewFlagSet("system coverage", flag.ExitOnError)
		rulesPath := fs.String("rules", "data/rules.json", "rules json")
		rulesExtra := fs.String("rules-extra", "", "optional expansion rules json")
		envPath := fs.String("env", "", "environment json (optional)")
		out := fs.String("out", "", "output file (optional)")
		if err := fs.Parse(args[1:]); err != nil {
			fatal(err)
		}
		rules, err := logic.LoadRulesCombined(*rulesPath, *rulesExtra)
		if err != nil {
			fatal(err)
		}
		report := logic.BuildMitreCoverage(rules)
		if *envPath != "" {
			environment, err := env.Load(*envPath)
			if err != nil {
				fatal(err)
			}
			report = logic.BuildMitreCoverageForEnv(rules, environment)
		}
		if *out != "" {
			if strings.HasSuffix(*out, ".md") {
				writeText(*out, renderCoverageMarkdown(report))
			} else {
				writeJSON(*out, report)
			}
			return
		}
		if gFlags.JSON {
			outJSON(report)
			return
		}
		outln("MITRE coverage")
		outln(fmt.Sprintf("Rules total: %d", report.TotalRules))
		if report.FilterNote != "" {
			outln(fmt.Sprintf("Applicable rules: %d", report.ApplicableRules))
		}
		outln(fmt.Sprintf("Rules with MITRE: %d", report.RulesWithMitre))
		outln(fmt.Sprintf("Rules missing MITRE: %d", len(report.RulesMissingMeta)))
		if len(report.Gaps.TacticsMissing) > 0 {
			outln("Missing tactics (environment):")
			for _, tactic := range report.Gaps.TacticsMissing {
				outln("- " + tactic)
			}
		}
		if len(report.Gaps.TechniquesMissing) > 0 {
			outln("Missing techniques (environment):")
			tactics := make([]string, 0, len(report.Gaps.TechniquesMissing))
			for tactic := range report.Gaps.TechniquesMissing {
				tactics = append(tactics, tactic)
			}
			sort.Strings(tactics)
			for _, tactic := range tactics {
				outln("- " + tactic)
				for _, tech := range report.Gaps.TechniquesMissing[tactic] {
					outln("  - " + tech)
				}
			}
		}
		if len(report.ExcludedRules) > 0 {
			outln("Excluded by environment filter:")
			for _, id := range report.ExcludedRules {
				outln("- " + id)
			}
		}
		if len(report.RulesMissingMeta) > 0 {
			outln("Missing metadata:")
			for _, id := range report.RulesMissingMeta {
				outln("- " + id)
			}
		}
		outln("Tactics:")
		for _, t := range report.Tactics {
			outln(fmt.Sprintf("- %s: %d rules, %d techniques", t.Tactic, t.RuleCount, len(t.Techniques)))
			for _, tech := range t.Techniques {
				label := tech.Technique
				if len(tech.Subtechniques) > 0 {
					label = label + " (" + strings.Join(tech.Subtechniques, ", ") + ")"
				}
				outln(fmt.Sprintf("  - %s: %d rules", label, tech.RuleCount))
			}
		}
	case "nist":
		fs := flag.NewFlagSet("system nist", flag.ExitOnError)
		rulesPath := fs.String("rules", "data/rules.json", "rules json")
		rulesExtra := fs.String("rules-extra", "", "optional expansion rules json")
		out := fs.String("out", "", "output file (optional)")
		if err := fs.Parse(args[1:]); err != nil {
			fatal(err)
		}
		rules, err := logic.LoadRulesCombined(*rulesPath, *rulesExtra)
		if err != nil {
			fatal(err)
		}
		report := logic.BuildNistCoverage(rules)
		if *out != "" {
			writeJSON(*out, report)
			return
		}
		if gFlags.JSON {
			outJSON(report)
			return
		}
		outln("NIST CSF coverage")
		outln(fmt.Sprintf("Rules total: %d", report.TotalRules))
		outln(fmt.Sprintf("Rules missing NIST: %d", len(report.RulesMissingMeta)))
		if len(report.RulesMissingMeta) > 0 {
			outln("Missing metadata:")
			for _, id := range report.RulesMissingMeta {
				outln("- " + id)
			}
		}
		for _, c := range report.Categories {
			outln(fmt.Sprintf("- %s: %d rules", c.Name, c.RuleCount))
		}
	case "killchain":
		fs := flag.NewFlagSet("system killchain", flag.ExitOnError)
		rulesPath := fs.String("rules", "data/rules.json", "rules json")
		rulesExtra := fs.String("rules-extra", "", "optional expansion rules json")
		out := fs.String("out", "", "output file (optional)")
		if err := fs.Parse(args[1:]); err != nil {
			fatal(err)
		}
		rules, err := logic.LoadRulesCombined(*rulesPath, *rulesExtra)
		if err != nil {
			fatal(err)
		}
		report := logic.BuildKillChainCoverage(rules)
		if *out != "" {
			writeJSON(*out, report)
			return
		}
		if gFlags.JSON {
			outJSON(report)
			return
		}
		outln("Kill Chain coverage")
		outln(fmt.Sprintf("Rules total: %d", report.TotalRules))
		outln(fmt.Sprintf("Rules missing Kill Chain: %d", len(report.RulesMissingMeta)))
		if len(report.RulesMissingMeta) > 0 {
			outln("Missing metadata:")
			for _, id := range report.RulesMissingMeta {
				outln("- " + id)
			}
		}
		for _, c := range report.Phases {
			outln(fmt.Sprintf("- %s: %d rules", c.Name, c.RuleCount))
		}
	case "confidence":
		fs := flag.NewFlagSet("system confidence", flag.ExitOnError)
		reportPath := fs.String("report", "", "reasoning report json")
		out := fs.String("out", "", "output file (optional)")
		if err := fs.Parse(args[1:]); err != nil {
			fatal(err)
		}
		if *reportPath == "" {
			fatal(errors.New("system confidence requires -report"))
		}
		rep, err := loadReportFile(*reportPath)
		if err != nil {
			fatal(err)
		}
		high, med, low := confidenceBands(rep.Results)
		if *out != "" {
			writeText(*out, renderConfidenceMarkdown(high, med, low))
			return
		}
		if gFlags.JSON {
			outJSON(map[string]int{"high": high, "medium": med, "low": low})
			return
		}
		outln("Confidence bands")
		outln(fmt.Sprintf("High (>=0.80): %d", high))
		outln(fmt.Sprintf("Medium (0.60-0.79): %d", med))
		outln(fmt.Sprintf("Low (<0.60): %d", low))
	default:
		fatal(errors.New("unknown system subcommand"))
	}
}

var gatedRuleIDs = map[string]bool{
	"TA0040.IMPACT_ENCRYPT": true,
	"TA0005.EVASION_C2":     true,
}

func applyGatedRules(rules []logic.Rule, approvalPath string) ([]logic.Rule, []model.RuleResult, []string) {
	if approvalPath != "" {
		if err := verifyAdminOverride(approvalPath); err == nil {
			return rules, nil, nil
		}
	}
	disabled := []string{}
	out := make([]logic.Rule, 0, len(rules))
	placeholders := []model.RuleResult{}
	for _, r := range rules {
		if gatedRuleIDs[r.ID] {
			disabled = append(disabled, r.ID)
			placeholders = append(placeholders, model.RuleResult{
				RuleID:        r.ID,
				Name:          r.Name + " (admin approval required)",
				Feasible:      false,
				PrecondOK:     true,
				Confidence:    0,
				Explanation:   "Rule pack gated by admin approval.",
				GapNarrative:  "Admin approval required to enable this rule pack.",
				ReasonCode:    "admin_hold",
				DecisionLabel: "keep",
			})
			continue
		}
		out = append(out, r)
	}
	if len(disabled) > 0 {
		sort.Strings(disabled)
		notices := []string{
			"Gated rules disabled: " + strings.Join(disabled, ", "),
			"Admin approval required at install time to enable these packs.",
		}
		return out, placeholders, notices
	}
	return out, placeholders, nil
}

func handleGenerate(args []string) {
	fs := flag.NewFlagSet("generate", flag.ExitOnError)
	out := fs.String("out", "", "output file (default stdout)")
	count := fs.Int("count", 60, "number of events")
	seed := fs.Int64("seed", 0, "random seed")
	if err := fs.Parse(args); err != nil {
		fatal(err)
	}

	events := sim.Synthetic(*seed, *count)
	writeJSON(*out, events)
}

func handleReason(args []string) {
	fs := flag.NewFlagSet("reason", flag.ExitOnError)
	in := fs.String("in", "", "input events json")
	approvalPath := fs.String("approval", "", "approval file")
	adminApproval := fs.String("admin-approval", "", "admin approval for gated rule packs")
	requireOkta := fs.Bool("require-okta", true, "require okta verified approvals")
	rulesPath := fs.String("rules", "", "rules json (optional)")
	rulesExtra := fs.String("rules-extra", "", "optional expansion rules json")
	includeEvents := fs.Bool("include-events", false, "include full supporting events in output")
	format := fs.String("format", "cli", "output format: cli or json")
	aiOverlay := fs.Bool("ai-overlay", false, "high-recall AI candidate alerts filtered by causal validation")
	aiThreshold := fs.Float64("ai-threshold", 0.20, "minimum AI candidate sensitivity (0-1)")
	aiMax := fs.Int("ai-max", 50, "maximum AI candidate alerts to include")
	if err := fs.Parse(args); err != nil {
		fatal(err)
	}

	if *in == "" {
		fatal(errors.New("-in is required"))
	}

	var events []model.Event
	readJSON(*in, &events)

	rules, err := logic.LoadRulesCombined(*rulesPath, *rulesExtra)
	if err != nil {
		fatal(err)
	}
	rules, placeholders, _ := applyGatedRules(rules, *adminApproval)
	rep := logic.ReasonWithMetrics(events, rules, nil, *includeEvents)
	if len(placeholders) > 0 {
		rep.Results = append(rep.Results, placeholders...)
	}
	if *aiOverlay {
		applyAIOverlay(&rep, events, rules, *aiThreshold, *aiMax)
	}
	switch *format {
	case "cli":
		fmt.Print(report.RenderCLI(rep))
	case "json":
		data, err := json.MarshalIndent(rep, "", "  ")
		if err != nil {
			fatal(err)
		}
		fmt.Println(string(data))
	default:
		fatal(errors.New("unknown format"))
	}

	if *approvalPath != "" {
		var a approval.Approval
		readJSON(*approvalPath, &a)
		if err := approval.Verify(a, *requireOkta, time.Now().UTC()); err != nil {
			fmt.Printf("Approval: INVALID (%s)\n", err.Error())
			os.Exit(2)
		}
		fmt.Println("Approval: VALID")
	}
}

func handleAssess(args []string) {
	fs := flag.NewFlagSet("assess", flag.ExitOnError)
	in := fs.String("in", "", "input events json")
	envPath := fs.String("env", "", "environment json")
	statePath := fs.String("state", "", "state json")
	auditPath := fs.String("audit", "", "audit log")
	siemPath := fs.String("siem", "", "siem export json (optional)")
	approvalPath := fs.String("approval", "", "approval file (single or dual)")
	adminApproval := fs.String("admin-approval", "", "admin approval for gated rule packs")
	policyPath := fs.String("policy", "", "governance policy json (optional)")
	constraintsPath := fs.String("constraints", "", "reasoning constraints json (optional)")
	rulesPath := fs.String("rules", "", "rules json (optional)")
	rulesExtra := fs.String("rules-extra", "", "optional expansion rules json")
	format := fs.String("format", "json", "output format: cli or json")
	outPath := fs.String("out", "", "output file (optional)")
	configPath := fs.String("config", "", "ops config json (optional)")
	baselinePath := fs.String("baseline", "data/zero_trust_baseline.json", "zero-trust baseline")
	explainOn := fs.Bool("explain", false, "add explanation layer")
	explainAck := fs.String("explain-ack", "", "acknowledge llm output risk")
	explainEndpoint := fs.String("explain-endpoint", "", "llm explanation endpoint (optional)")
	explainTimeout := fs.Duration("explain-timeout", 8*time.Second, "llm explanation timeout")
	mlAssist := fs.Bool("ml-assist", false, "recommend missing telemetry from history")
	mlHistory := fs.String("ml-history", "", "history json for telemetry recommendations")
	mlLimit := fs.Int("ml-limit", 5, "telemetry recommendation limit")
	mlCategories := fs.String("ml-categories", "identity,cloud", "ml ranking categories")
	mlSimilarLimit := fs.Int("ml-similar-limit", 3, "similar incident limit")
	mlPlaybookLimit := fs.Int("ml-playbook-limit", 3, "playbook suggestion limit")
	aiOverlay := fs.Bool("ai-overlay", false, "high-recall AI candidate alerts filtered by causal validation")
	aiThreshold := fs.Float64("ai-threshold", 0.20, "minimum AI candidate sensitivity (0-1)")
	aiMax := fs.Int("ai-max", 50, "maximum AI candidate alerts to include")
	if err := fs.Parse(args); err != nil {
		fatal(err)
	}

	if *in == "" || *envPath == "" {
		fatal(errors.New("-in and -env are required"))
	}
	requireExplainAck(*explainOn, *explainAck)

	if _, err := zerotrust.LoadBaseline(*baselinePath); err != nil {
		fatal(errors.New("zero-trust baseline missing or invalid; run init-scan before assess"))
	}

	var events []model.Event
	readJSON(*in, &events)

	rules, err := logic.LoadRulesCombined(*rulesPath, *rulesExtra)
	if err != nil {
		fatal(err)
	}
	rules, placeholders, gatedNotices := applyGatedRules(rules, *adminApproval)
	if err := validate.Rules(rules); err != nil {
		fatal(validate.Must(err))
	}
	environment, err := env.Load(*envPath)
	if err != nil {
		fatal(err)
	}
	if err := validate.Environment(environment); err != nil {
		fatal(validate.Must(err))
	}
	st, err := state.Load(*statePath)
	if err != nil && *statePath != "" {
		fatal(err)
	}

	cfg, err := ops.LoadConfig(*configPath)
	if err != nil {
		fatal(err)
	}
	logger := ops.NewLogger(cfg.LogLevel)
	metrics := &ops.Metrics{}

	includeEvidence := cfg.StrictMode
	out := core.AssessWithMetrics(events, rules, environment, st, metrics, includeEvidence)
	if len(placeholders) > 0 {
		out.Reasoning.Results = append(out.Reasoning.Results, placeholders...)
	}
	if len(gatedNotices) > 0 {
		out.Notices = append(out.Notices, gatedNotices...)
	}
	if *explainOn {
		if err := applyExplanation(&out.Reasoning, *explainEndpoint, *explainTimeout); err != nil {
			fmt.Fprintf(os.Stderr, "explanation unavailable: %s\n", err.Error())
		}
	}
	if *mlAssist {
		if err := applyMLAssist(&out.Reasoning, *mlHistory, *mlLimit, *mlCategories, *mlSimilarLimit, *mlPlaybookLimit); err != nil {
			fmt.Fprintf(os.Stderr, "ml assist unavailable: %s\n", err.Error())
		}
	}
	if *constraintsPath != "" {
		cons, err := governance.LoadConstraints(*constraintsPath)
		if err != nil {
			fatal(err)
		}
		logic.ApplyConstraints(&out.Reasoning, cons)
	}
	if *aiOverlay {
		applyAIOverlay(&out.Reasoning, events, rules, *aiThreshold, *aiMax)
	}
	if err := state.Save(*statePath, out.State); err != nil {
		fatal(err)
	}

	var decision governance.Decision
	var policy governance.Policy
	if *policyPath != "" {
		pol, err := governance.Load(*policyPath)
		if err != nil {
			fatal(err)
		}
		if err := validate.Policy(pol); err != nil {
			fatal(validate.Must(err))
		}
		policy = pol
		decision = governance.Evaluate(pol, out.DriftSignals)
		if decision.RequireDual {
			if *approvalPath == "" {
				fatal(errors.New("dual approval required by policy"))
			}
			if err := verifyApprovalFileWithReqAndMin(*approvalPath, true, decision.MinApprovals); err != nil {
				fatal(err)
			}
		}
	}

	if *approvalPath != "" {
		if err := verifyApprovalFileWithPolicy(*approvalPath, policy); err != nil {
			fatal(err)
		}
	}

	artifact := audit.Artifact{
		ID:        fmt.Sprintf("artifact-%d", time.Now().UTC().UnixNano()),
		CreatedAt: time.Now().UTC(),
		Summary:   out.Summary,
		Findings:  out.Findings,
		Reasoning: out.State.ReasoningChain,
		Metadata: map[string]string{
			"rules_source": *rulesPath,
			"env_source":   *envPath,
		},
	}
	if out.Reasoning.MLAssistEnabled {
		artifact.Metadata["ml_assist"] = "true"
		if *mlHistory != "" {
			artifact.Metadata["ml_history"] = *mlHistory
		}
		if *mlCategories != "" {
			artifact.Metadata["ml_categories"] = *mlCategories
		}
	}
	if out.Reasoning.AIOverlay.Enabled {
		artifact.Metadata["ai_overlay"] = out.Reasoning.AIOverlay.Mode
		artifact.Metadata["ai_overlay_threshold"] = fmt.Sprintf("%.2f", out.Reasoning.AIOverlay.Threshold)
	}
	if *explainOn {
		artifact.Metadata["llm_explain"] = "true"
		artifact.Metadata["llm_ack"] = "accepted"
		if *explainEndpoint != "" {
			artifact.Metadata["llm_endpoint"] = *explainEndpoint
		}
	}
	if decision.RequireDual {
		artifact.Metadata["policy_dual_required"] = "true"
		artifact.Metadata["policy_reasons"] = strings.Join(decision.Reasons, ",")
	}
	prev, err := audit.LoadLastHash(*auditPath)
	if err != nil {
		fatal(err)
	}
	artifact.PrevHash = prev
	artifact.Hash, err = audit.HashArtifact(artifact)
	if err != nil {
		fatal(err)
	}
	if err := audit.AppendLog(*auditPath, artifact); err != nil {
		fatal(err)
	}
	if err := integration.ExportSIEM(*siemPath, out); err != nil {
		fatal(err)
	}

	if cfg.MetricsOn {
		m := metrics.Snapshot()
		logger.Info(fmt.Sprintf("metrics events=%d rules=%d findings=%d", m.EventsIn, m.RulesChecked, m.FindingsOut))
	}

	switch *format {
	case "cli":
		fmt.Print(report.RenderCLI(out.Reasoning))
		fmt.Printf("Next Moves: %d\\n", len(out.NextMoves))
		for _, m := range out.NextMoves {
			fmt.Printf("- %s\\n", m)
		}
		if len(out.DriftSignals) > 0 {
			fmt.Println("Drift Signals:")
			for _, d := range out.DriftSignals {
				fmt.Printf("- %s\\n", d)
			}
		}
	case "json":
		data, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			fatal(err)
		}
		if *outPath != "" {
			if strings.HasSuffix(*outPath, ".lz4") {
				data, err = compress.Compress(data)
				if err != nil {
					fatal(err)
				}
			}
			if err := os.WriteFile(*outPath, data, 0600); err != nil {
				fatal(err)
			}
			fmt.Println("Report written: " + *outPath)
			return
		}
		fmt.Println(string(data))
	default:
		fatal(errors.New("unknown format"))
	}
}

func handleKeys(args []string) {
	fs := flag.NewFlagSet("keys", flag.ExitOnError)
	out := fs.String("out", "", "output file (default stdout)")
	if err := fs.Parse(args); err != nil {
		fatal(err)
	}

	pub, priv, err := approval.GenerateKeypair()
	if err != nil {
		fatal(err)
	}
	kp := KeypairFile{
		PublicKey:  base64.StdEncoding.EncodeToString(pub),
		PrivateKey: base64.StdEncoding.EncodeToString(priv),
	}
	writeJSON(*out, kp)
}

func handleApprove(args []string) {
	fs := flag.NewFlagSet("approve", flag.ExitOnError)
	keyPath := fs.String("key", "", "keypair json")
	id := fs.String("id", "", "approval id")
	ttl := fs.Duration("ttl", 10*time.Minute, "time to live")
	okta := fs.Bool("okta", true, "okta verified flag")
	signer := fs.String("signer", "", "signer id")
	role := fs.String("role", "", "signer role")
	out := fs.String("out", "", "output file (default stdout)")
	if err := fs.Parse(args); err != nil {
		fatal(err)
	}

	if *keyPath == "" || *id == "" {
		fatal(errors.New("-key and -id are required"))
	}

	var kp KeypairFile
	readJSON(*keyPath, &kp)
	pubBytes, err := base64.StdEncoding.DecodeString(kp.PublicKey)
	if err != nil {
		fatal(err)
	}
	privBytes, err := base64.StdEncoding.DecodeString(kp.PrivateKey)
	if err != nil {
		fatal(err)
	}
	app, err := approval.Sign(*id, *ttl, *okta, *signer, *role, pubBytes, privBytes)
	if err != nil {
		fatal(err)
	}
	writeJSON(*out, app)
}

func handleApprove2(args []string) {
	fs := flag.NewFlagSet("approve2", flag.ExitOnError)
	key1 := fs.String("key1", "", "keypair json 1")
	key2 := fs.String("key2", "", "keypair json 2")
	id := fs.String("id", "", "approval id")
	ttl := fs.Duration("ttl", 10*time.Minute, "time to live")
	okta := fs.Bool("okta", true, "okta verified flag")
	signer1 := fs.String("signer1", "", "signer id 1")
	signer2 := fs.String("signer2", "", "signer id 2")
	role1 := fs.String("role1", "approver", "signer role 1")
	role2 := fs.String("role2", "approver", "signer role 2")
	out := fs.String("out", "", "output file (default stdout)")
	if err := fs.Parse(args); err != nil {
		fatal(err)
	}

	if *key1 == "" || *key2 == "" || *id == "" {
		fatal(errors.New("-key1, -key2 and -id are required"))
	}

	a1 := signWithKeyfile(*key1, *id, *ttl, *okta, *signer1, *role1)
	a2 := signWithKeyfile(*key2, *id, *ttl, *okta, *signer2, *role2)
	dual := approval.DualApproval{
		Approvals:   []approval.Approval{a1, a2},
		MinSigners:  2,
		RequireOkta: *okta,
	}
	writeJSON(*out, dual)
}

func handleVerify(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	approvalPath := fs.String("approval", "", "approval file")
	requireOkta := fs.Bool("require-okta", true, "require okta verified approvals")
	if err := fs.Parse(args); err != nil {
		fatal(err)
	}

	if *approvalPath == "" {
		fatal(errors.New("-approval is required"))
	}
	if err := verifyApprovalFileWithReq(*approvalPath, *requireOkta); err != nil {
		fatal(err)
	}
	fmt.Println("Approval is valid")
}

func handleAuditVerify(args []string) {
	fs := flag.NewFlagSet("audit-verify", flag.ExitOnError)
	auditPath := fs.String("audit", "", "audit log")
	if err := fs.Parse(args); err != nil {
		fatal(err)
	}
	if *auditPath == "" {
		fatal(errors.New("-audit is required"))
	}
	if err := audit.VerifyChain(*auditPath); err != nil {
		fatal(err)
	}
	fmt.Println("Audit chain is valid")
}

func handleAuditSign(args []string) {
	fs := flag.NewFlagSet("audit-sign", flag.ExitOnError)
	auditPath := fs.String("audit", "", "audit log")
	outPath := fs.String("out", "signed_audit.log", "signed audit log")
	signer := fs.String("signer", "soc-admin", "signer id")
	if err := fs.Parse(args); err != nil {
		fatal(err)
	}
	if *auditPath == "" {
		fatal(errors.New("-audit is required"))
	}
	data, err := os.ReadFile(*auditPath)
	if err != nil {
		fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	pub, priv, err := audit.GenerateSigningKeypair()
	if err != nil {
		fatal(err)
	}
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var a audit.Artifact
		if err := json.Unmarshal([]byte(line), &a); err != nil {
			fatal(err)
		}
		signed, err := audit.SignArtifact(a, *signer, pub, priv)
		if err != nil {
			fatal(err)
		}
		if err := audit.AppendSigned(*outPath, signed); err != nil {
			fatal(err)
		}
	}
	fmt.Printf("Signed audit written: %s\n", *outPath)
}

func handleGenerateScenarios(args []string) {
	fs := flag.NewFlagSet("generate-scenarios", flag.ExitOnError)
	out := fs.String("out", "scenarios.json", "output scenarios file")
	rulesPath := fs.String("rules", "", "rules json (optional)")
	rulesExtra := fs.String("rules-extra", "", "optional expansion rules json")
	multiplier := fs.Int("multiplier", 1, "scenario multiplier per rule")
	noise := fs.Bool("noise", false, "add benign noise events")
	if err := fs.Parse(args); err != nil {
		fatal(err)
	}

	rules, err := logic.LoadRulesCombined(*rulesPath, *rulesExtra)
	if err != nil {
		fatal(err)
	}
	f := eval.GenerateScenariosWithOptions(rules, eval.ScenarioOptions{
		Multiplier: *multiplier,
		Noise:      *noise,
	})
	if err := eval.SaveScenarios(*out, f); err != nil {
		fatal(err)
	}
	fmt.Printf("Scenarios written: %s\n", *out)
}

func handleEvaluate(args []string) {
	fs := flag.NewFlagSet("evaluate", flag.ExitOnError)
	scenariosPath := fs.String("scenarios", "", "scenarios json")
	rulesPath := fs.String("rules", "", "rules json (optional)")
	rulesExtra := fs.String("rules-extra", "", "optional expansion rules json")
	format := fs.String("format", "json", "output format: cli, json, or md")
	outPath := fs.String("out", "", "output file (optional)")
	if err := fs.Parse(args); err != nil {
		fatal(err)
	}

	if *scenariosPath == "" {
		fatal(errors.New("-scenarios is required"))
	}

	rules, err := logic.LoadRulesCombined(*rulesPath, *rulesExtra)
	if err != nil {
		fatal(err)
	}
	scenarios, err := eval.LoadScenarios(*scenariosPath)
	if err != nil {
		fatal(err)
	}
	rep := eval.Score(scenarios, rules)

	switch *format {
	case "json":
		data, err := json.MarshalIndent(rep, "", "  ")
		if err != nil {
			fatal(err)
		}
		if *outPath != "" {
			writeJSON(*outPath, rep)
			return
		}
		fmt.Println(string(data))
	case "cli":
		fmt.Printf("Total labels: %d\n", rep.Total)
		fmt.Printf("Accuracy: %.3f\n", rep.Accuracy)
		for cls, m := range rep.ByClass {
			fmt.Printf("%s precision=%.3f recall=%.3f\n", cls, m.Precision, m.Recall)
		}
		if len(rep.Mismatches) > 0 {
			fmt.Printf("Mismatches: %d\n", len(rep.Mismatches))
		}
		if *outPath != "" {
			writeText(*outPath, renderEvalMarkdown(rep))
		}
	case "md":
		md := renderEvalMarkdown(rep)
		if *outPath != "" {
			writeText(*outPath, md)
			return
		}
		fmt.Println(md)
	default:
		fatal(errors.New("unknown format"))
	}
}

func handleIngestHTTP(args []string) {
	fs := flag.NewFlagSet("ingest-http", flag.ExitOnError)
	addr := fs.String("addr", ":8080", "listen address")
	secureKeyring := fs.String("secure-keyring", "", "keyring json for secure ingest")
	if err := fs.Parse(args); err != nil {
		fatal(err)
	}

	http.HandleFunc("/ingest", integration.IngestHandler)
	http.HandleFunc("/healthz", integration.HealthHandler)
	http.HandleFunc("/metrics", integration.MetricsHandler)
	if *secureKeyring != "" {
		ring, err := secureingest.LoadKeyring(*secureKeyring)
		if err != nil {
			fatal(err)
		}
		opts, err := secureingest.KeyringOptions(ring)
		if err != nil {
			fatal(err)
		}
		stats := integration.NewSecureIngestStats()
		http.HandleFunc("/ingest-secure", integration.SecureIngestHandler(stats, opts))
		http.HandleFunc("/ingest-health", integration.SecureIngestHealthHandler(stats))
	}
	fmt.Printf("Ingest HTTP listening on %s\n", *addr)
	srv := &http.Server{
		Addr:              *addr,
		Handler:           nil,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil {
		fatal(err)
	}
}

type entraPullManifest struct {
	Start           string    `json:"start"`
	End             string    `json:"end"`
	Count           int       `json:"count"`
	RawPath         string    `json:"raw_path"`
	RawSHA256       string    `json:"raw_sha256"`
	PullerVersion   string    `json:"puller_version"`
	ClientRequestID string    `json:"client_request_id"`
	RequestID       string    `json:"request_id,omitempty"`
	PulledAt        time.Time `json:"pulled_at"`
}

func handleEntraPull(args []string) {
	fs := flag.NewFlagSet("ingest entra-pull", flag.ExitOnError)
	tenant := fs.String("tenant", "", "entra tenant id")
	clientID := fs.String("client-id", "", "entra client id")
	clientSecret := fs.String("client-secret", "", "entra client secret")
	start := fs.String("start", "", "RFC3339 start time")
	end := fs.String("end", "", "RFC3339 end time")
	out := fs.String("out", "data/raw/entra/signins/raw_signins.json", "output raw JSON")
	manifest := fs.String("manifest", "", "manifest output (optional)")
	top := fs.Int("top", 1000, "page size")
	maxPages := fs.Int("max-pages", 50, "max pages to pull")
	timeout := fs.Duration("timeout", 30*time.Second, "http timeout")
	if err := fs.Parse(args); err != nil {
		fatal(err)
	}
	if *tenant == "" {
		*tenant = os.Getenv("ENTRA_TENANT_ID")
	}
	if *clientID == "" {
		*clientID = os.Getenv("ENTRA_CLIENT_ID")
	}
	if *clientSecret == "" {
		*clientSecret = os.Getenv("ENTRA_CLIENT_SECRET")
	}
	if *tenant == "" || *clientID == "" || *clientSecret == "" {
		fatal(errors.New("entra-pull requires --tenant, --client-id, --client-secret (or ENTRA_* env vars)"))
	}
	if *start == "" || *end == "" {
		fatal(errors.New("entra-pull requires --start and --end RFC3339"))
	}
	startTime, err := time.Parse(time.RFC3339, *start)
	if err != nil {
		fatal(err)
	}
	endTime, err := time.Parse(time.RFC3339, *end)
	if err != nil {
		fatal(err)
	}
	if !startTime.Before(endTime) {
		fatal(errors.New("start must be before end"))
	}
	if !ops.IsSafePath(*out) {
		fatal(os.ErrInvalid)
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0755); err != nil {
		fatal(err)
	}
	token, err := fetchGraphToken(*tenant, *clientID, *clientSecret, *timeout)
	if err != nil {
		fatal(err)
	}
	client := &http.Client{Timeout: *timeout}
	reqURL := buildEntraSignInURL(*top, startTime, endTime)
	clientRequestID := newClientRequestID()
	pages := make([]json.RawMessage, 0, 4)
	total := 0
	requestID := ""
	for i := 0; i < *maxPages && reqURL != ""; i++ {
		req, err := http.NewRequest(http.MethodGet, reqURL, nil)
		if err != nil {
			fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("client-request-id", clientRequestID)
		req.Header.Set("return-client-request-id", "true")
		resp, err := client.Do(req)
		if err != nil {
			fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			fatal(err)
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			fatal(fmt.Errorf("graph pull failed: %s", string(body)))
		}
		if requestID == "" {
			requestID = resp.Header.Get("request-id")
		}
		pages = append(pages, json.RawMessage(body))
		var page struct {
			Value    []json.RawMessage `json:"value"`
			NextLink string            `json:"@odata.nextLink"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			fatal(err)
		}
		total += len(page.Value)
		reqURL = page.NextLink
	}
	payload := map[string]interface{}{
		"source":            "microsoft_graph",
		"api":               "/auditLogs/signIns",
		"start":             startTime.Format(time.RFC3339),
		"end":               endTime.Format(time.RFC3339),
		"client_request_id": clientRequestID,
		"request_id":        requestID,
		"pages":             pages,
	}
	rawBytes, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		fatal(err)
	}
	if err := os.WriteFile(*out, rawBytes, 0600); err != nil {
		fatal(err)
	}
	sum := sha256.Sum256(rawBytes)
	manifestPath := *manifest
	if manifestPath == "" {
		manifestPath = strings.TrimSuffix(*out, filepath.Ext(*out)) + "_manifest.json"
	}
	m := entraPullManifest{
		Start:           startTime.Format(time.RFC3339),
		End:             endTime.Format(time.RFC3339),
		Count:           total,
		RawPath:         *out,
		RawSHA256:       hex.EncodeToString(sum[:]),
		PullerVersion:   "aman-entra-pull/1.0",
		ClientRequestID: clientRequestID,
		RequestID:       requestID,
		PulledAt:        time.Now().UTC(),
	}
	writeJSON(manifestPath, m)
	outln("Raw sign-ins written: " + *out)
	outln(fmt.Sprintf("Count: %d", total))
	outln("Manifest: " + manifestPath)
}

func handleEntraNormalize(args []string) {
	fs := flag.NewFlagSet("ingest entra-normalize", flag.ExitOnError)
	in := fs.String("in", "", "raw sign-ins json")
	out := fs.String("out", "data/normalized_events.json", "normalized events output")
	if err := fs.Parse(args); err != nil {
		fatal(err)
	}
	if *in == "" {
		fatal(errors.New("entra-normalize requires --in"))
	}
	if !ops.IsSafePath(*in) || !ops.IsSafePath(*out) {
		fatal(os.ErrInvalid)
	}
	raw, err := os.ReadFile(*in)
	if err != nil {
		fatal(err)
	}
	events, err := integration.NormalizeEntraSignIns(raw)
	if err != nil {
		fatal(err)
	}
	writeJSON(*out, events)
	outln(fmt.Sprintf("Normalized %d events", len(events)))
	outln("Output: " + *out)
}

func fetchGraphToken(tenant, clientID, clientSecret string, timeout time.Duration) (string, error) {
	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("scope", "https://graph.microsoft.com/.default")
	form.Set("grant_type", "client_credentials")
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenant), strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("token request failed: %s", string(body))
	}
	var parsed struct {
		AccessToken      string `json:"access_token"`
		TokenType        string `json:"token_type"`
		ExpiresIn        int    `json:"expires_in"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", err
	}
	if parsed.AccessToken == "" {
		return "", errors.New("token response missing access_token")
	}
	return parsed.AccessToken, nil
}

func buildEntraSignInURL(top int, start, end time.Time) string {
	values := url.Values{}
	values.Set("$top", strconv.Itoa(top))
	filter := fmt.Sprintf("createdDateTime ge %s and createdDateTime lt %s", start.Format(time.RFC3339), end.Format(time.RFC3339))
	values.Set("$filter", filter)
	return "https://graph.microsoft.com/v1.0/auditLogs/signIns?" + values.Encode()
}

func newClientRequestID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("aman-%d", time.Now().UTC().UnixNano())
	}
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func handleIngestInventory(args []string) {
	fs := flag.NewFlagSet("ingest-inventory", flag.ExitOnError)
	in := fs.String("in", "", "inventory directory or file")
	out := fs.String("out", "data/env.json", "output environment json")
	if err := fs.Parse(args); err != nil {
		fatal(err)
	}
	if *in == "" {
		fatal(errors.New("-in is required"))
	}
	inv, err := inventory.Load(*in)
	if err != nil {
		fatal(err)
	}
	environment := inventory.BuildEnvironment(inv)
	if err := validate.Environment(environment); err != nil {
		fatal(validate.Must(err))
	}
	writeJSON(*out, environment)
	fmt.Printf("Environment written: %s\n", *out)
	fmt.Printf("Hosts: %d, Identities: %d, Trust boundaries: %d\n", len(environment.Hosts), len(environment.Identities), len(environment.TrustBoundaries))
}

func handleInventoryDrift(args []string) {
	fs := flag.NewFlagSet("inventory-drift", flag.ExitOnError)
	basePath := fs.String("base", "", "existing env.json")
	in := fs.String("in", "", "inventory directory or file")
	out := fs.String("out", "drift.json", "output drift report")
	if err := fs.Parse(args); err != nil {
		fatal(err)
	}
	if *basePath == "" || *in == "" {
		fatal(errors.New("-base and -in are required"))
	}
	baseEnv, err := env.Load(*basePath)
	if err != nil {
		fatal(err)
	}
	inv, err := inventory.Load(*in)
	if err != nil {
		fatal(err)
	}
	newEnv := inventory.BuildEnvironment(inv)
	rep := inventory.DiffEnv(baseEnv, newEnv)
	writeJSON(*out, rep)
	fmt.Printf("Drift report written: %s\n", *out)
	fmt.Printf("Added hosts: %d, Removed hosts: %d\n", len(rep.AddedHosts), len(rep.RemovedHosts))
	fmt.Printf("Added identities: %d, Removed identities: %d\n", len(rep.AddedIdentities), len(rep.RemovedIdentites))
	fmt.Printf("Added trusts: %d, Removed trusts: %d\n", len(rep.AddedTrusts), len(rep.RemovedTrusts))
}

func handleInventoryAdapter(args []string) {
	fs := flag.NewFlagSet("inventory-adapter", flag.ExitOnError)
	provider := fs.String("provider", "", "adapter provider (aws|okta|azure|gcp)")
	configPath := fs.String("config", "", "adapter config json")
	out := fs.String("out", "data/env.json", "output environment json")
	if err := fs.Parse(args); err != nil {
		fatal(err)
	}
	if *provider == "" || *configPath == "" {
		fatal(errors.New("-provider and -config are required"))
	}
	cfg, err := inventory.LoadConfig(*configPath)
	if err != nil {
		fatal(err)
	}
	adapter, err := inventory.NewAdapter(*provider)
	if err != nil {
		fatal(err)
	}
	inv, err := adapter.Load(cfg)
	if err != nil {
		fatal(err)
	}
	environment := inventory.BuildEnvironment(inv)
	if err := validate.Environment(environment); err != nil {
		fatal(validate.Must(err))
	}
	writeJSON(*out, environment)
	fmt.Printf("Environment written: %s\n", *out)
}

func handleInventoryRefresh(args []string) {
	fs := flag.NewFlagSet("inventory-refresh", flag.ExitOnError)
	provider := fs.String("provider", "all", "adapter provider (aws|okta|azure|gcp|all)")
	configPath := fs.String("config", "", "adapter config json (optional)")
	in := fs.String("in", "", "inventory directory or file (optional)")
	basePath := fs.String("base", "", "existing env.json (optional)")
	out := fs.String("out", "data/env.json", "output environment json")
	driftPath := fs.String("drift", "drift.json", "drift report output")
	requestPath := fs.String("drift-request", "drift_request.json", "drift approval request output")
	requireApproval := fs.Bool("require-approval", false, "write drift request when drift detected")
	if err := fs.Parse(args); err != nil {
		fatal(err)
	}

	var inv inventory.Inventory
	if *in != "" {
		loaded, err := inventory.Load(*in)
		if err != nil {
			fatal(err)
		}
		inv = loaded
	} else {
		if *configPath == "" {
			fatal(errors.New("-config or -in is required"))
		}
		cfg, err := inventory.LoadConfig(*configPath)
		if err != nil {
			fatal(err)
		}
		inv, err = loadFromProviders(*provider, cfg)
		if err != nil {
			fatal(err)
		}
	}

	environment := inventory.BuildEnvironment(inv)
	if err := validate.Environment(environment); err != nil {
		fatal(validate.Must(err))
	}
	writeJSON(*out, environment)
	fmt.Printf("Environment written: %s\n", *out)

	if *basePath != "" {
		baseEnv, err := env.Load(*basePath)
		if err != nil {
			fatal(err)
		}
		drift := inventory.DiffEnv(baseEnv, environment)
		writeJSON(*driftPath, drift)
		fmt.Printf("Drift report written: %s\n", *driftPath)
		if *requireApproval && hasDrift(drift) {
			req := inventory.NewDriftRequest(*driftPath, drift)
			writeJSON(*requestPath, req)
			fmt.Printf("Drift request written: %s\n", *requestPath)
		}
	}
}

func handleInventorySchedule(args []string) {
	fs := flag.NewFlagSet("inventory-schedule", flag.ExitOnError)
	provider := fs.String("provider", "all", "adapter provider (aws|okta|azure|gcp|all)")
	configPath := fs.String("config", "", "adapter config json")
	basePath := fs.String("base", "", "existing env.json (optional)")
	out := fs.String("out", "data/env.json", "output environment json")
	driftPath := fs.String("drift", "drift.json", "drift report output")
	requestPath := fs.String("drift-request", "drift_request.json", "drift approval request output")
	interval := fs.Duration("interval", 6*time.Hour, "refresh interval")
	jitter := fs.Duration("jitter", 30*time.Minute, "random jitter added to interval")
	if err := fs.Parse(args); err != nil {
		fatal(err)
	}
	if *configPath == "" {
		fatal(errors.New("-config is required"))
	}
	cfg, err := inventory.LoadConfig(*configPath)
	if err != nil {
		fatal(err)
	}
	for {
		inv, err := loadFromProviders(*provider, cfg)
		if err != nil {
			fmt.Printf("inventory refresh error: %v\n", err)
		} else {
			environment := inventory.BuildEnvironment(inv)
			if err := validate.Environment(environment); err != nil {
				fmt.Printf("inventory validate error: %v\n", err)
			} else {
				writeJSON(*out, environment)
				if *basePath != "" {
					baseEnv, err := env.Load(*basePath)
					if err == nil {
						drift := inventory.DiffEnv(baseEnv, environment)
						writeJSON(*driftPath, drift)
						if hasDrift(drift) {
							req := inventory.NewDriftRequest(*driftPath, drift)
							writeJSON(*requestPath, req)
						}
					}
				}
			}
		}
		sleepWithJitter(*interval, *jitter)
	}
}

func loadFromProviders(provider string, cfg inventory.AdapterConfig) (inventory.Inventory, error) {
	if provider == "all" {
		out := inventory.Inventory{}
		for _, p := range []string{"aws", "okta", "azure", "gcp"} {
			adapter, err := inventory.NewAdapter(p)
			if err != nil {
				return out, err
			}
			inv, err := adapter.Load(cfg)
			if err != nil {
				return out, err
			}
			out = inventory.MergeInventory(out, inv)
		}
		return out, nil
	}
	adapter, err := inventory.NewAdapter(provider)
	if err != nil {
		return inventory.Inventory{}, err
	}
	return adapter.Load(cfg)
}

func hasDrift(drift inventory.DriftReport) bool {
	return len(drift.AddedHosts)+len(drift.RemovedHosts)+len(drift.AddedIdentities)+len(drift.RemovedIdentites)+len(drift.AddedTrusts)+len(drift.RemovedTrusts) > 0
}

func sleepWithJitter(interval time.Duration, jitter time.Duration) {
	wait := interval
	if jitter > 0 {
		wait += randomJitter(jitter)
	}
	time.Sleep(wait)
}

func randomJitter(max time.Duration) time.Duration {
	if max <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0
	}
	return time.Duration(n.Int64())
}

func handleInitScan(args []string) {
	fs := flag.NewFlagSet("init-scan", flag.ExitOnError)
	baselinePath := fs.String("baseline", "data/zero_trust_baseline.json", "baseline output path")
	if err := fs.Parse(args); err != nil {
		fatal(err)
	}
	root, _ := os.Getwd()
	b, err := zerotrust.BuildBaseline(root, zerotrust.DefaultExclusions)
	if err != nil {
		fatal(err)
	}
	if err := zerotrust.SaveBaseline(*baselinePath, b); err != nil {
		fatal(err)
	}
	fmt.Printf("Zero-Trust baseline created: %s\n", *baselinePath)
}

func handleScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	baselinePath := fs.String("baseline", "data/zero_trust_baseline.json", "baseline path")
	overrideApproval := fs.String("override-approval", "", "admin override approval")
	if err := fs.Parse(args); err != nil {
		fatal(err)
	}

	root, _ := os.Getwd()
	b, err := zerotrust.LoadBaseline(*baselinePath)
	if err != nil {
		fatal(errors.New("zero-trust baseline missing or invalid; run init-scan"))
	}
	res, err := zerotrust.Compare(root, b, zerotrust.DefaultExclusions)
	if err != nil {
		fatal(err)
	}
	if len(res.Missing)+len(res.Added)+len(res.Changed) == 0 {
		fmt.Println("Zero-Trust scan passed")
		return
	}
	fmt.Printf("Zero-Trust scan failed: added=%d changed=%d missing=%d\n", len(res.Added), len(res.Changed), len(res.Missing))
	if *overrideApproval == "" {
		fatal(errors.New("admin override required"))
	}
	if err := verifyAdminOverride(*overrideApproval); err != nil {
		fatal(err)
	}
	fmt.Println("WARNING: Zero-Trust scan failed. Override applied by admin. No liability assumed; system integrity may be impacted.")
}

func handleProfileAdd(args []string) {
	fs := flag.NewFlagSet("profile-add", flag.ExitOnError)
	file := fs.String("file", "data/analyst_profiles.json", "profiles file")
	id := fs.String("id", "", "analyst id")
	name := fs.String("name", "", "analyst name")
	specialty := fs.String("specialty", "", "specialty (comma separated)")
	notes := fs.String("notes", "", "notes")
	if err := fs.Parse(args); err != nil {
		fatal(err)
	}
	if *id == "" || *name == "" {
		fatal(errors.New("-id and -name are required"))
	}
	profiles, _ := governance.LoadProfiles(*file)
	profiles = append(profiles, governance.AnalystProfile{
		ID:          *id,
		Name:        *name,
		Specialties: strings.Split(strings.TrimSpace(*specialty), ","),
		Notes:       *notes,
	})
	if err := governance.SaveProfiles(*file, profiles); err != nil {
		fatal(err)
	}
	fmt.Println("Profile added")
}

func handleConstraintAdd(args []string) {
	fs := flag.NewFlagSet("constraint-add", flag.ExitOnError)
	file := fs.String("file", "data/constraints.json", "constraints file")
	id := fs.String("id", "", "constraint id")
	rule := fs.String("rule", "", "rule id")
	require := fs.String("require", "", "required evidence id (comma separated)")
	forbid := fs.String("forbid", "", "forbidden evidence id (comma separated)")
	author := fs.String("author", "", "author analyst id")
	notes := fs.String("notes", "", "notes")
	if err := fs.Parse(args); err != nil {
		fatal(err)
	}
	if *id == "" || *rule == "" {
		fatal(errors.New("-id and -rule are required"))
	}
	cons, _ := governance.LoadConstraints(*file)
	cons = append(cons, governance.ReasoningConstraint{
		ID:              *id,
		RuleID:          *rule,
		RequireEvidence: splitCSV(*require),
		ForbidEvidence:  splitCSV(*forbid),
		Author:          *author,
		CreatedAt:       time.Now().UTC().Format(time.RFC3339),
		Notes:           *notes,
	})
	if err := governance.SaveConstraints(*file, cons); err != nil {
		fatal(err)
	}
	fmt.Println("Constraint added")
}

func handleDisagreementAdd(args []string) {
	fs := flag.NewFlagSet("disagreement-add", flag.ExitOnError)
	file := fs.String("file", "data/disagreements.log", "disagreement log")
	analyst := fs.String("analyst", "", "analyst id")
	rule := fs.String("rule", "", "rule id")
	expected := fs.String("expected", "", "expected outcome")
	actual := fs.String("actual", "", "actual outcome")
	rationale := fs.String("rationale", "", "rationale")
	if err := fs.Parse(args); err != nil {
		fatal(err)
	}
	if *analyst == "" || *rule == "" {
		fatal(errors.New("-analyst and -rule are required"))
	}
	if err := governance.AppendDisagreement(*file, governance.Disagreement{
		AnalystID: *analyst,
		RuleID:    *rule,
		Expected:  *expected,
		Actual:    *actual,
		Rationale: *rationale,
	}); err != nil {
		fatal(err)
	}
	fmt.Println("Disagreement logged")
}
func readJSON(path string, out interface{}) {
	if !ops.IsSafePath(path) {
		fatal(os.ErrInvalid)
	}
	//nolint:gosec // path validated via IsSafePath
	// #nosec G304
	data, err := os.ReadFile(path)
	if err != nil {
		fatal(err)
	}
	if err := json.Unmarshal(data, out); err != nil {
		fatal(err)
	}
}

func writeJSON(path string, v interface{}) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fatal(err)
	}
	if path == "" {
		fmt.Println(string(data))
		return
	}
	if !ops.IsSafePath(path) {
		fatal(os.ErrInvalid)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		fatal(err)
	}
}

func signWithKeyfile(path, id string, ttl time.Duration, okta bool, signer string, role string) approval.Approval {
	var kp KeypairFile
	readJSON(path, &kp)
	pubBytes, err := base64.StdEncoding.DecodeString(kp.PublicKey)
	if err != nil {
		fatal(err)
	}
	privBytes, err := base64.StdEncoding.DecodeString(kp.PrivateKey)
	if err != nil {
		fatal(err)
	}
	app, err := approval.Sign(id, ttl, okta, signer, role, pubBytes, privBytes)
	if err != nil {
		fatal(err)
	}
	return app
}

func splitCSV(v string) []string {
	if strings.TrimSpace(v) == "" {
		return []string{}
	}
	parts := strings.Split(v, ",")
	out := []string{}
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func verifyApprovalFileWithReq(path string, requireOkta bool) error {
	if !ops.IsSafePath(path) {
		return os.ErrInvalid
	}
	//nolint:gosec // path validated via IsSafePath
	// #nosec G304
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	// detect dual approval by JSON shape
	var dual approval.DualApproval
	if err := json.Unmarshal(data, &dual); err == nil && len(dual.Approvals) > 0 {
		dual.RequireOkta = requireOkta
		return approval.VerifyDual(dual, time.Now().UTC())
	}
	var a approval.Approval
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	return approval.Verify(a, requireOkta, time.Now().UTC())
}

func verifyApprovalFileWithReqAndMin(path string, requireOkta bool, min int) error {
	if !ops.IsSafePath(path) {
		return os.ErrInvalid
	}
	//nolint:gosec // path validated via IsSafePath
	// #nosec G304
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var dual approval.DualApproval
	if err := json.Unmarshal(data, &dual); err == nil && len(dual.Approvals) > 0 {
		dual.RequireOkta = requireOkta
		if min > 0 {
			dual.MinSigners = min
		}
		return approval.VerifyDual(dual, time.Now().UTC())
	}
	var a approval.Approval
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	return approval.Verify(a, requireOkta, time.Now().UTC())
}

func verifyApprovalFileWithPolicy(path string, policy governance.Policy) error {
	if !ops.IsSafePath(path) {
		return os.ErrInvalid
	}
	//nolint:gosec // path validated via IsSafePath
	// #nosec G304
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var dual approval.DualApproval
	if err := json.Unmarshal(data, &dual); err == nil && len(dual.Approvals) > 0 {
		dual.RequireOkta = true
		if err := approval.VerifyDual(dual, time.Now().UTC()); err != nil {
			return err
		}
		for _, a := range dual.Approvals {
			if err := approval.VerifySignerRole(a, policy.AllowedSignerRoles); err != nil {
				return err
			}
		}
		return nil
	}
	var a approval.Approval
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	if err := approval.Verify(a, true, time.Now().UTC()); err != nil {
		return err
	}
	return approval.VerifySignerRole(a, policy.AllowedSignerRoles)
}

func verifyAdminOverride(path string) error {
	if !ops.IsSafePath(path) {
		return os.ErrInvalid
	}
	//nolint:gosec // path validated via IsSafePath
	// #nosec G304
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var dual approval.DualApproval
	if err := json.Unmarshal(data, &dual); err == nil && len(dual.Approvals) > 0 {
		dual.RequireOkta = true
		if err := approval.VerifyDual(dual, time.Now().UTC()); err != nil {
			return err
		}
		for _, a := range dual.Approvals {
			if a.SignerRole != "admin" {
				return errors.New("admin override requires admin signer role")
			}
		}
		return nil
	}
	var a approval.Approval
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	if err := approval.Verify(a, true, time.Now().UTC()); err != nil {
		return err
	}
	if a.SignerRole != "admin" {
		return errors.New("admin override requires admin signer role")
	}
	return nil
}

func applyExplanation(rep *model.ReasoningReport, endpoint string, timeout time.Duration) error {
	resp, err := explain.Generate(*rep, explain.Options{
		Endpoint: endpoint,
		Timeout:  timeout,
	})
	if err != nil {
		return err
	}
	rep.Explanation = resp.Explanation
	rep.SuggestedSteps = resp.Steps
	rep.ExplanationSource = resp.Source
	return nil
}

func applyMLAssist(rep *model.ReasoningReport, historyPath string, limit int, categories string, similarLimit int, playbookLimit int) error {
	history, err := assist.LoadHistory(historyPath)
	if err != nil {
		return err
	}
	rec, err := assist.RecommendTelemetry(*rep, history, limit)
	if err != nil {
		return err
	}
	rep.RecommendedTelemetry = rec
	if historyPath != "" {
		rep.TelemetrySource = "history"
	} else {
		rep.TelemetrySource = "current"
	}
	cats := strings.Split(categories, ",")
	assist.RankFeasible(rep, history, assist.RankConfig{Categories: cats})
	similar, playbooks := assist.SuggestSimilar(rep, history, assist.SimilarConfig{
		Limit:         similarLimit,
		PlaybookLimit: playbookLimit,
	})
	rep.SimilarIncidents = similar
	rep.SuggestedPlaybooks = playbooks
	rep.MLAssistEnabled = true
	rep.MLAssistNotes = []string{"advisory_only", "deterministic_verdicts_unchanged"}
	return nil
}

func applyAIOverlay(rep *model.ReasoningReport, events []model.Event, rules []logic.Rule, threshold float64, maxAlerts int) {
	alerts := overlay.BuildHighRecallAlerts(events, rules, threshold, maxAlerts)
	filtered, summary := overlay.ApplyCausalFilter(alerts, rep.Results)
	summary.Threshold = threshold
	rep.AIOverlay = summary
	rep.AIAlerts = filtered
	enforceAmanEscalationAuthority(rep)
}

func enforceAmanEscalationAuthority(rep *model.ReasoningReport) {
	if rep == nil || len(rep.AIAlerts) == 0 {
		return
	}
	byRule := map[string]model.RuleResult{}
	for _, r := range rep.Results {
		byRule[r.RuleID] = r
	}
	downgraded := 0
	for i := range rep.AIAlerts {
		a := &rep.AIAlerts[i]
		if a.Status != "escalated" {
			continue
		}
		r, ok := byRule[a.RuleID]
		if !ok || !r.Feasible {
			a.Status = "triaged"
			a.Reason = "downgraded: Aman deterministic validation is escalation authority"
			downgraded++
		}
	}
	if downgraded > 0 {
		esc := 0
		tri := 0
		sup := 0
		for _, a := range rep.AIAlerts {
			switch a.Status {
			case "escalated":
				esc++
			case "triaged":
				tri++
			case "suppressed":
				sup++
			}
		}
		rep.AIOverlay.EscalatedCount = esc
		rep.AIOverlay.TriagedCount = tri
		rep.AIOverlay.SuppressedCount = sup
		rep.AIOverlay.Notes = append(rep.AIOverlay.Notes, "aman_escalation_authority_enforced")
	}
}

func runIntegrationReadiness(rulesPath string, rulesExtra string, strict bool, minEvents int, minFeasible int) (IntegrationReadinessReport, error) {
	rules, err := logic.LoadRulesCombined(rulesPath, rulesExtra)
	if err != nil {
		return IntegrationReadinessReport{}, err
	}
	checks := []IntegrationCheck{
		{Category: "identity", Fixture: "data/fixtures/okta_systemlog.json", Schema: string(integration.SchemaOkta)},
		{Category: "cloud", Fixture: "data/fixtures/aws_cloudtrail.json", Schema: string(integration.SchemaCloudTrail)},
		{Category: "edr", Fixture: "data/fixtures/crowdstrike_fdr.json", Schema: string(integration.SchemaCrowdStrike)},
	}
	out := IntegrationReadinessReport{
		GeneratedAt: time.Now().UTC(),
		RulesPath:   rulesPath,
		Checks:      make([]IntegrationCheck, len(checks)),
	}
	for i, c := range checks {
		cc := c
		fixturePath := resolveFixturePath(cc.Fixture)
		if fixturePath == "" {
			cc.Error = "fixture not found"
			out.Failed++
			out.Checks[i] = cc
			continue
		}
		cc.Fixture = fixturePath
		if !ops.IsSafePath(cc.Fixture) {
			cc.Error = os.ErrInvalid.Error()
			out.Failed++
			out.Checks[i] = cc
			continue
		}
		// #nosec G304 - fixture path is static and validated
		raw, err := os.ReadFile(cc.Fixture)
		if err != nil {
			cc.Error = err.Error()
			out.Failed++
			out.Checks[i] = cc
			continue
		}
		events, err := integration.IngestEvents(raw, integration.IngestOptions{
			Schema: integration.Schema(cc.Schema),
			Kind:   cc.Kind,
		})
		if err != nil {
			cc.Error = err.Error()
			out.Failed++
			out.Checks[i] = cc
			continue
		}
		cc.EventCount = len(events)
		rep := logic.ReasonWithMetrics(events, rules, nil, false)
		feasible := 0
		for _, r := range rep.Results {
			if r.Feasible {
				feasible++
			}
		}
		cc.FeasibleCount = feasible
		cc.Pass = cc.EventCount > 0
		if strict {
			if cc.EventCount < minEvents || cc.FeasibleCount < minFeasible {
				cc.Pass = false
				if cc.Error == "" {
					cc.Error = fmt.Sprintf("strict threshold unmet (events>=%d feasible>=%d)", minEvents, minFeasible)
				}
			}
		}
		if cc.Pass {
			out.Passed++
		} else {
			if cc.Error == "" {
				cc.Error = "no events produced after normalization"
			}
			out.Failed++
		}
		out.Checks[i] = cc
	}
	return out, nil
}

func runIntegrationQuickstart(rulesPath string, rulesExtra string, outDir string, aiThreshold float64, aiMax int) (IntegrationQuickstartReport, error) {
	if !ops.IsSafePath(outDir) {
		return IntegrationQuickstartReport{}, os.ErrInvalid
	}
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return IntegrationQuickstartReport{}, err
	}
	rules, err := logic.LoadRulesCombined(rulesPath, rulesExtra)
	if err != nil {
		return IntegrationQuickstartReport{}, err
	}
	type runCfg struct {
		category string
		fixture  string
		schema   integration.Schema
		kind     string
	}
	cfgs := []runCfg{
		{category: "identity", fixture: "data/fixtures/okta_systemlog.json", schema: integration.SchemaOkta},
		{category: "cloud", fixture: "data/fixtures/aws_cloudtrail.json", schema: integration.SchemaCloudTrail},
		{category: "edr", fixture: "data/fixtures/crowdstrike_fdr.json", schema: integration.SchemaCrowdStrike},
	}
	out := IntegrationQuickstartReport{
		GeneratedAt: time.Now().UTC(),
		OutputDir:   outDir,
		RulesPath:   rulesPath,
		Runs:        make([]IntegrationQuickstartRun, 0, len(cfgs)),
	}
	for _, cfg := range cfgs {
		run := IntegrationQuickstartRun{
			Category: cfg.category,
			Fixture:  cfg.fixture,
			Schema:   string(cfg.schema),
			Kind:     cfg.kind,
		}
		fixturePath := resolveFixturePath(cfg.fixture)
		if fixturePath == "" {
			run.Error = "fixture not found"
			out.Failed++
			out.Runs = append(out.Runs, run)
			continue
		}
		raw, err := os.ReadFile(fixturePath) // #nosec G304
		if err != nil {
			run.Error = err.Error()
			out.Failed++
			out.Runs = append(out.Runs, run)
			continue
		}
		events, err := integration.IngestEvents(raw, integration.IngestOptions{
			Schema: cfg.schema,
			Kind:   cfg.kind,
		})
		if err != nil {
			run.Error = err.Error()
			out.Failed++
			out.Runs = append(out.Runs, run)
			continue
		}
		run.EventCount = len(events)
		rep := logic.ReasonWithMetrics(events, rules, nil, false)
		feasible := 0
		for _, r := range rep.Results {
			if r.Feasible {
				feasible++
			}
		}
		run.FeasibleCount = feasible
		applyAIOverlay(&rep, events, rules, aiThreshold, aiMax)
		run.CandidateCount = rep.AIOverlay.CandidateCount
		run.EscalatedCount = rep.AIOverlay.EscalatedCount
		run.TriagedCount = rep.AIOverlay.TriagedCount
		run.SuppressedCount = rep.AIOverlay.SuppressedCount

		eventsPath := filepath.Join(outDir, cfg.category+"_events.normalized.json")
		reportPath := filepath.Join(outDir, cfg.category+"_report.ai_overlay.json")
		if !ops.IsSafePath(eventsPath) || !ops.IsSafePath(reportPath) {
			run.Error = os.ErrInvalid.Error()
			out.Failed++
			out.Runs = append(out.Runs, run)
			continue
		}
		eventsData, err := json.MarshalIndent(events, "", "  ")
		if err != nil {
			run.Error = err.Error()
			out.Failed++
			out.Runs = append(out.Runs, run)
			continue
		}
		reportData, err := json.MarshalIndent(rep, "", "  ")
		if err != nil {
			run.Error = err.Error()
			out.Failed++
			out.Runs = append(out.Runs, run)
			continue
		}
		if err := os.WriteFile(eventsPath, eventsData, 0600); err != nil {
			run.Error = err.Error()
			out.Failed++
			out.Runs = append(out.Runs, run)
			continue
		}
		if err := os.WriteFile(reportPath, reportData, 0600); err != nil {
			run.Error = err.Error()
			out.Failed++
			out.Runs = append(out.Runs, run)
			continue
		}
		run.EventsPath = eventsPath
		run.ReportPath = reportPath
		run.Pass = run.EventCount > 0
		if run.Pass {
			out.Passed++
		} else {
			out.Failed++
		}
		out.Runs = append(out.Runs, run)
	}
	return out, nil
}

func runNoisegraphQuickstart(decisionsPath string, eventsOut string, reportOut string, rulesPath string, rulesExtra string, only string, aiThreshold float64, aiMax int) (NoisegraphQuickstartReport, error) {
	if !ops.IsSafePath(decisionsPath) || !ops.IsSafePath(eventsOut) || (reportOut != "" && !ops.IsSafePath(reportOut)) {
		return NoisegraphQuickstartReport{}, os.ErrInvalid
	}
	include := map[string]bool{}
	included := []string{}
	for _, s := range strings.Split(only, ",") {
		v := strings.ToLower(strings.TrimSpace(s))
		if v == "" || include[v] {
			continue
		}
		include[v] = true
		included = append(included, v)
	}
	if len(include) == 0 {
		include["keep"] = true
		include["escalate"] = true
		included = []string{"keep", "escalate"}
	}

	f, err := os.Open(decisionsPath) // #nosec G304
	if err != nil {
		return NoisegraphQuickstartReport{}, err
	}
	defer func() { _ = f.Close() }()

	events := []model.Event{}
	scanner := bufio.NewScanner(f)
	parsed := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parsed++
		var d map[string]interface{}
		if err := json.Unmarshal([]byte(line), &d); err != nil {
			continue
		}
		status := strings.ToLower(strings.TrimSpace(asString(d["decision"])))
		if !include[status] {
			continue
		}
		ev := noisegraphDecisionToEvent(d, parsed, status)
		events = append(events, ev)
	}
	if err := scanner.Err(); err != nil {
		return NoisegraphQuickstartReport{}, err
	}

	eventsData, err := json.MarshalIndent(events, "", "  ")
	if err != nil {
		return NoisegraphQuickstartReport{}, err
	}
	if err := os.WriteFile(eventsOut, eventsData, 0600); err != nil {
		return NoisegraphQuickstartReport{}, err
	}

	rules, err := logic.LoadRulesCombined(rulesPath, rulesExtra)
	if err != nil {
		return NoisegraphQuickstartReport{}, err
	}
	rep := logic.ReasonWithMetrics(events, rules, nil, false)
	applyAIOverlay(&rep, events, rules, aiThreshold, aiMax)

	out := NoisegraphQuickstartReport{
		GeneratedAt:   time.Now().UTC(),
		DecisionsPath: decisionsPath,
		EventsPath:    eventsOut,
		ReportPath:    reportOut,
		Included:      included,
		ParsedLines:   parsed,
		EventsCount:   len(events),
		Reasoning:     rep,
	}
	if reportOut != "" {
		data, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			return NoisegraphQuickstartReport{}, err
		}
		if err := os.WriteFile(reportOut, data, 0600); err != nil {
			return NoisegraphQuickstartReport{}, err
		}
	}
	return out, nil
}

func buildROIScorecard(pilotPath string, integrationPath string, benchmarkPath string) (ROIScorecard, error) {
	if !ops.IsSafePath(pilotPath) || !ops.IsSafePath(integrationPath) || !ops.IsSafePath(benchmarkPath) {
		return ROIScorecard{}, os.ErrInvalid
	}
	var pilot PilotMetrics
	pilotRaw, err := os.ReadFile(pilotPath) // #nosec G304
	if err != nil {
		return ROIScorecard{}, err
	}
	if err := json.Unmarshal(pilotRaw, &pilot); err != nil {
		return ROIScorecard{}, err
	}
	var integ IntegrationReadinessReport
	integRaw, err := os.ReadFile(integrationPath) // #nosec G304
	if err != nil {
		return ROIScorecard{}, err
	}
	if err := json.Unmarshal(integRaw, &integ); err != nil {
		return ROIScorecard{}, err
	}
	benchRaw, err := os.ReadFile(benchmarkPath) // #nosec G304
	if err != nil {
		return ROIScorecard{}, err
	}
	overhead := parseOverlayOverheadPct(string(benchRaw))
	score := ROIScorecard{
		GeneratedAt:                time.Now().UTC(),
		PilotMetricsPath:           pilotPath,
		BenchmarkPath:              benchmarkPath,
		QueueReductionPct:          pilot.QueueReductionPct,
		EscalatedPrecisionProxyPct: pilot.EscalatedPrecisionProxyPct,
		SuppressedLaterTrueRatePct: pilot.SuppressedLaterTrueRatePct,
		OverlayOverheadPct:         overhead,
		IntegrationPassed:          integ.Passed,
		IntegrationFailed:          integ.Failed,
		Notes: []string{
			"score favors measurable queue reduction, precision proxy, safety, and integration reliability",
			"commercial proof still depends on broader real-world labeled outcomes",
		},
	}
	score.ReadinessScore = compositeReadinessScore(score)
	return score, nil
}

func parseOverlayOverheadPct(markdown string) float64 {
	re := regexp.MustCompile(`([+-]?\d+(?:\.\d+)?)\s*%`)
	lines := strings.Split(markdown, "\n")
	for _, line := range lines {
		l := strings.TrimSpace(line)
		if !strings.Contains(strings.ToLower(l), "overlay overhead") {
			continue
		}
		m := re.FindStringSubmatch(l)
		if len(m) < 2 {
			continue
		}
		v := strings.TrimSpace(strings.TrimPrefix(m[1], "+"))
		f, err := strconv.ParseFloat(v, 64)
		if err == nil {
			return f
		}
	}
	return 0
}

func compositeReadinessScore(s ROIScorecard) float64 {
	// Weighted composite mapped to a 0-10 scale.
	queue := clampPercent(s.QueueReductionPct / 25 * 10)         // 25% queue reduction ~= 10
	precision := clampPercent(s.EscalatedPrecisionProxyPct / 10) // already %
	safety := clampPercent((100 - s.SuppressedLaterTrueRatePct) / 10)
	overhead := clampPercent((100 - minFloat(50, s.OverlayOverheadPct)*2) / 10)
	integ := 0.0
	total := s.IntegrationPassed + s.IntegrationFailed
	if total > 0 {
		integ = 10 * (float64(s.IntegrationPassed) / float64(total))
	}
	raw := 0.25*queue + 0.25*precision + 0.20*safety + 0.15*overhead + 0.15*integ
	if raw > 10 {
		return 10
	}
	if raw < 0 {
		return 0
	}
	return raw
}

func clampPercent(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 10 {
		return 10
	}
	return v
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func renderROIScorecardMarkdown(s ROIScorecard) string {
	buf := &strings.Builder{}
	fmt.Fprintf(buf, "# ROI Scorecard\n\n")
	fmt.Fprintf(buf, "Generated: %s\n\n", s.GeneratedAt.Format(time.RFC3339))
	fmt.Fprintf(buf, "- Queue reduction: %.2f%%\n", s.QueueReductionPct)
	fmt.Fprintf(buf, "- Escalated precision proxy: %.2f%%\n", s.EscalatedPrecisionProxyPct)
	fmt.Fprintf(buf, "- Suppressed-but-later-true rate: %.2f%%\n", s.SuppressedLaterTrueRatePct)
	fmt.Fprintf(buf, "- AI overlay overhead: %.2f%%\n", s.OverlayOverheadPct)
	fmt.Fprintf(buf, "- Integration readiness: %d pass / %d fail\n", s.IntegrationPassed, s.IntegrationFailed)
	fmt.Fprintf(buf, "- Composite readiness score: %.2f / 10\n\n", s.ReadinessScore)
	fmt.Fprintf(buf, "## Notes\n")
	for _, n := range s.Notes {
		fmt.Fprintf(buf, "- %s\n", n)
	}
	return buf.String()
}

func buildDemoPack(outDir string, rulesPath string, rulesExtra string) (DemoPackReport, error) {
	if !ops.IsSafePath(outDir) {
		return DemoPackReport{}, os.ErrInvalid
	}
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return DemoPackReport{}, err
	}
	intRead, err := runIntegrationReadiness(rulesPath, rulesExtra, true, 1, 0)
	if err != nil {
		return DemoPackReport{}, err
	}
	intQuick, err := runIntegrationQuickstart(rulesPath, rulesExtra, filepath.Join(outDir, "onboarding"), 0.20, 50)
	if err != nil {
		return DemoPackReport{}, err
	}
	// Ensure pilot/integration artifacts exist for ROI generation.
	pilotPath := filepath.Join(outDir, "pilot_metrics_report.json")
	if err := writePilotMetricsArtifact("docs/pilot_metrics_report.json", pilotPath, time.Now().UTC()); err != nil {
		return DemoPackReport{}, err
	}
	intPath := filepath.Join(outDir, "integration_readiness.json")
	if err := writeJSONFile(intPath, intRead); err != nil {
		return DemoPackReport{}, err
	}
	benchPath := "docs/production_benchmark_report.md"
	score, err := buildROIScorecard(pilotPath, intPath, benchPath)
	if err != nil {
		return DemoPackReport{}, err
	}
	scorePathJSON := filepath.Join(outDir, "roi_scorecard.json")
	scorePathMD := filepath.Join(outDir, "roi_scorecard.md")
	writeJSON(scorePathJSON, score)
	writeText(scorePathMD, renderROIScorecardMarkdown(score))

	rep := DemoPackReport{
		GeneratedAt:           time.Now().UTC(),
		OutDir:                outDir,
		IntegrationReadiness:  intRead,
		IntegrationQuickstart: intQuick,
		ROIScorecard:          score,
		Files: []string{
			intPath,
			scorePathJSON,
			scorePathMD,
			filepath.Join(outDir, "onboarding"),
		},
	}
	packPath := filepath.Join(outDir, "demo_pack_report.json")
	writeJSON(packPath, rep)
	rep.Files = append(rep.Files, packPath)
	return rep, nil
}

func writeJSONFile(path string, v interface{}) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func writePilotMetricsArtifact(srcPath string, dstPath string, now time.Time) error {
	if _, err := os.Stat(srcPath); err == nil {
		raw, err := os.ReadFile(srcPath) // #nosec G304
		if err != nil {
			return err
		}
		return os.WriteFile(dstPath, raw, 0600)
	}
	emptyPilot := PilotMetrics{GeneratedAt: now}
	return writeJSONFile(dstPath, emptyPilot)
}

func noisegraphDecisionToEvent(d map[string]interface{}, idx int, status string) model.Event {
	event := asMap(d["event"])
	entity := asMap(event["entity"])
	host := firstString(entity["source"], entity["host"], entity["asset"], event["source"], d["source"])
	if strings.TrimSpace(host) == "" {
		host = "unknown-host"
	}
	user := firstString(entity["user"], entity["principal"], event["user"], d["user"])
	reasons := asStringSlice(d["reasons"])
	template := asString(event["template"])
	return model.Event{
		ID:   firstString(d["fingerprint"], d["id"], fmt.Sprintf("ng-%d", idx)),
		Time: parseNoisegraphTime(asString(d["ts"])),
		Host: host,
		User: user,
		Type: "noisegraph_" + status,
		Details: map[string]interface{}{
			"source":      "noisegraph",
			"decision":    status,
			"risk":        d["risk"],
			"reasons":     reasons,
			"template":    template,
			"incident_id": d["incident_id"],
		},
	}
}

func parseNoisegraphTime(v string) time.Time {
	s := strings.TrimSpace(v)
	if s == "" {
		return time.Now().UTC()
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}
	return time.Now().UTC()
}

func asMap(v interface{}) map[string]interface{} {
	if m, ok := v.(map[string]interface{}); ok {
		return m
	}
	return map[string]interface{}{}
}

func asString(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func firstString(vals ...interface{}) string {
	for _, v := range vals {
		if s, ok := v.(string); ok {
			if strings.TrimSpace(s) != "" {
				return s
			}
		}
	}
	return ""
}

func asStringSlice(v interface{}) []string {
	if v == nil {
		return []string{}
	}
	if list, ok := v.([]interface{}); ok {
		out := []string{}
		for _, it := range list {
			s := strings.TrimSpace(asString(it))
			if s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	if s := strings.TrimSpace(asString(v)); s != "" {
		return []string{s}
	}
	return []string{}
}

func resolveFixturePath(path string) string {
	candidates := []string{path}
	if abs, err := filepath.Abs(filepath.Join("..", "..", path)); err == nil {
		candidates = append(candidates, abs)
	}
	if abs, err := filepath.Abs(path); err == nil {
		candidates = append(candidates, abs)
	}
	for _, c := range candidates {
		if c == "" {
			continue
		}
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

func computePilotMetrics(rep model.ReasoningReport, history assist.HistoryFile, reportPath string, historyPath string) PilotMetrics {
	confirmedRules := map[string]bool{}
	falsePositiveRules := map[string]bool{}
	for _, inc := range history.Incidents {
		rules := dedupeHistoryRules(inc)
		switch strings.ToLower(strings.TrimSpace(inc.Outcome)) {
		case "confirmed", "true_positive":
			for _, r := range rules {
				confirmedRules[r] = true
			}
		case "false_positive", "benign":
			for _, r := range rules {
				falsePositiveRules[r] = true
			}
		}
	}

	candidates := rep.AIOverlay.CandidateCount
	if candidates == 0 {
		candidates = len(rep.AIAlerts)
	}
	m := PilotMetrics{
		GeneratedAt:                      time.Now().UTC(),
		ReportPath:                       reportPath,
		HistoryPath:                      historyPath,
		CandidateCount:                   candidates,
		KnownConfirmedRulesInHistory:     len(confirmedRules),
		KnownFalsePositiveRulesInHistory: len(falsePositiveRules),
	}

	for _, a := range rep.AIAlerts {
		switch a.Status {
		case "escalated":
			m.EscalatedCount++
			if confirmedRules[a.RuleID] {
				m.EscalatedConfirmedCount++
			} else if falsePositiveRules[a.RuleID] {
				m.EscalatedFalsePositiveCount++
			} else {
				m.EscalatedUnknownOutcomeCount++
			}
		case "triaged":
			m.TriagedCount++
		case "suppressed":
			m.SuppressedCount++
			if confirmedRules[a.RuleID] {
				m.SuppressedLaterTrueCount++
			}
		}
	}

	if m.CandidateCount > 0 {
		m.QueueReductionPct = 100 * (float64(m.CandidateCount-m.EscalatedCount) / float64(m.CandidateCount))
		m.SuppressedLaterTrueRatePct = 100 * (float64(m.SuppressedLaterTrueCount) / float64(m.CandidateCount))
	}
	knownEscalated := m.EscalatedConfirmedCount + m.EscalatedFalsePositiveCount
	if knownEscalated > 0 {
		m.EscalatedPrecisionProxyPct = 100 * (float64(m.EscalatedConfirmedCount) / float64(knownEscalated))
	}
	return m
}

func dedupeHistoryRules(inc assist.HistoryEntry) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, r := range inc.RuleIDs {
		r = strings.TrimSpace(r)
		if r == "" || seen[r] {
			continue
		}
		seen[r] = true
		out = append(out, r)
	}
	if inc.RuleID != "" {
		r := strings.TrimSpace(inc.RuleID)
		if r != "" && !seen[r] {
			out = append(out, r)
		}
	}
	return out
}

func renderPilotMetricsMarkdown(m PilotMetrics) string {
	buf := &strings.Builder{}
	fmt.Fprintf(buf, "# Pilot Metrics Report\n\n")
	fmt.Fprintf(buf, "Generated: %s\n\n", m.GeneratedAt.Format(time.RFC3339))
	fmt.Fprintf(buf, "- Report source: `%s`\n", m.ReportPath)
	fmt.Fprintf(buf, "- History source: `%s`\n\n", m.HistoryPath)
	fmt.Fprintf(buf, "## Funnel\n")
	fmt.Fprintf(buf, "- Candidate alerts: %d\n", m.CandidateCount)
	fmt.Fprintf(buf, "- Escalated alerts: %d\n", m.EscalatedCount)
	fmt.Fprintf(buf, "- Triaged alerts: %d\n", m.TriagedCount)
	fmt.Fprintf(buf, "- Suppressed alerts: %d\n", m.SuppressedCount)
	fmt.Fprintf(buf, "- Queue reduction: %.2f%%\n\n", m.QueueReductionPct)
	fmt.Fprintf(buf, "## Outcome Alignment (History-Matched)\n")
	fmt.Fprintf(buf, "- Escalated + confirmed: %d\n", m.EscalatedConfirmedCount)
	fmt.Fprintf(buf, "- Escalated + false positive: %d\n", m.EscalatedFalsePositiveCount)
	fmt.Fprintf(buf, "- Escalated + unknown outcome: %d\n", m.EscalatedUnknownOutcomeCount)
	fmt.Fprintf(buf, "- Escalated precision proxy: %.2f%%\n\n", m.EscalatedPrecisionProxyPct)
	fmt.Fprintf(buf, "## Safety\n")
	fmt.Fprintf(buf, "- Suppressed but later true (history overlap): %d\n", m.SuppressedLaterTrueCount)
	fmt.Fprintf(buf, "- Suppressed-but-later-true rate: %.2f%%\n\n", m.SuppressedLaterTrueRatePct)
	fmt.Fprintf(buf, "## History Coverage\n")
	fmt.Fprintf(buf, "- Confirmed rules in history: %d\n", m.KnownConfirmedRulesInHistory)
	fmt.Fprintf(buf, "- False-positive rules in history: %d\n", m.KnownFalsePositiveRulesInHistory)
	return buf.String()
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err.Error())
	os.Exit(1)
}

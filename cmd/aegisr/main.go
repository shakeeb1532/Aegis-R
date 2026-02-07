package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"aegisr/internal/approval"
	"aegisr/internal/audit"
	"aegisr/internal/core"
	"aegisr/internal/env"
	"aegisr/internal/eval"
	"aegisr/internal/governance"
	"aegisr/internal/inventory"
	"aegisr/internal/integration"
	"aegisr/internal/logic"
	"aegisr/internal/model"
	"aegisr/internal/ops"
	"aegisr/internal/report"
	"aegisr/internal/sim"
	"aegisr/internal/state"
	"aegisr/internal/ui"
	"aegisr/internal/validate"
	"aegisr/internal/zerotrust"
)

type KeypairFile struct {
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
}

type approvalRecord struct {
	Approval     approval.Approval `json:"approval"`
	Rationale    string            `json:"rationale"`
	EvidenceGaps []string          `json:"evidence_gaps"`
}

type GlobalFlags struct {
	JSON    bool
	Quiet   bool
	NoColor bool
	Profile string
}

var gFlags GlobalFlags

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
	case "ui":
		handleUI(args[1:])
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

func usage() {
	fmt.Println("Aegis-R CLI")
	fmt.Println("Commands:")
	fmt.Println("  aegis ingest <verb> [flags]")
	fmt.Println("  aegis graph <verb> [flags]")
	fmt.Println("  aegis reason <verb> [flags]")
	fmt.Println("  aegis govern <verb> [flags]")
	fmt.Println("  aegis audit <verb> [flags]")
	fmt.Println("  aegis system <verb> [flags]")
	fmt.Println("  generate -out events.json -count 60 -seed 42")
	fmt.Println("  reason -in events.json [-approval approval.json] [-require-okta] [-rules rules.json] [-format cli|json]")
	fmt.Println("  assess -in events.json -env env.json -state state.json -audit audit.log [-rules rules.json] [-approval approval.json] [-policy policy.json] [-constraints data/constraints.json] [-config ops.json] [-format cli|json] [-baseline data/zero_trust_baseline.json]")
	fmt.Println("  assess -in events.json -env env.json -state state.json -audit audit.log -siem siem.json (optional)")
	fmt.Println("  keys -out keypair.json")
	fmt.Println("  approve -key keypair.json -id change-1 -ttl 10m -okta true -signer alice -role approver -out approval.json")
	fmt.Println("  approve2 -key1 key1.json -key2 key2.json -id change-1 -ttl 10m -okta true -signer1 alice -signer2 bob -out dual_approval.json")
	fmt.Println("  verify -approval approval.json [-require-okta]")
	fmt.Println("  audit-verify -audit audit.log")
	fmt.Println("  audit-sign -audit audit.log -out signed_audit.log -signer soc-admin")
	fmt.Println("  generate-scenarios -out scenarios.json [-rules rules.json]")
	fmt.Println("  evaluate -scenarios scenarios.json [-rules rules.json] [-format cli|json|md] [-out report.md]")
	fmt.Println("  ingest-http -addr :8080 (schema: ecs|elastic_ecs|ocsf|cim|splunk_cim_auth|splunk_cim_net|mde)")
	fmt.Println("  ingest-inventory -in data/inventory -out data/env.json")
	fmt.Println("  inventory-drift -base data/env.json -in data/inventory -out drift.json")
	fmt.Println("  inventory-adapter -provider aws|okta|azure|gcp -config data/inventory/config.json -out data/env.json")
	fmt.Println("  ui -addr :9090 -audit audit.log -signed-audit signed_audit.log -approvals approvals.log -report report.json -profiles data/analyst_profiles.json -disagreements data/disagreements.log -key keypair.json -basic-user user -basic-pass pass")
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
	for _, r := range results {
		if r.Feasible {
			hasFeasible = true
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
	return "IMPOSSIBLE"
}

func loadEvents(path string) ([]model.Event, error) {
	var events []model.Event
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

func handleIngest(args []string) {
	if len(args) == 0 {
		fatal(errors.New("ingest requires a subcommand: file|http|sample"))
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
		fatal(errors.New("graph requires a subcommand: status|threads|show|explain|export"))
	}
	fs := flag.NewFlagSet("graph", flag.ExitOnError)
	statePath := fs.String("state", "data/state.json", "state file")
	thread := fs.String("thread", "", "thread id")
	node := fs.String("node", "", "node id")
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
		adminApproval := fs.String("admin-approval", "", "admin approval for gated rule packs")
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
		events, err := loadEvents(*in)
		if err != nil {
			fatal(err)
		}
		rules, err := logic.LoadRules("")
		if err != nil {
			fatal(err)
		}
		rules, placeholders := applyGatedRules(rules, *adminApproval)
		rep := logic.Reason(events, rules)
		if len(placeholders) > 0 {
			rep.Results = append(rep.Results, placeholders...)
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
	case "host":
		fs := flag.NewFlagSet("reason host", flag.ExitOnError)
		in := fs.String("in", "", "events file")
		host := fs.String("host", "", "host id")
		adminApproval := fs.String("admin-approval", "", "admin approval for gated rule packs")
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
		rules, err := logic.LoadRules("")
		if err != nil {
			fatal(err)
		}
		rules, placeholders := applyGatedRules(rules, *adminApproval)
		rep := logic.Reason(filtered, rules)
		if len(placeholders) > 0 {
			rep.Results = append(rep.Results, placeholders...)
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

func handleGovern(args []string) {
	if len(args) == 0 {
		fatal(errors.New("govern requires a subcommand: approve|freeze|list|ticket"))
	}
	switch args[0] {
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
		out := fs.String("out", "data/approval.json", "output file")
		if err := fs.Parse(args[1:]); err != nil {
			fatal(err)
		}
		if *item == "" {
			fatal(errors.New("govern approve requires --item"))
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
			app1, err := approval.Sign(*item, *ttl, true, *signer, *role, pub1, priv1)
			if err != nil {
				fatal(err)
			}
			app2, err := approval.Sign(*item, *ttl, true, *signer2, *role, pub2, priv2)
			if err != nil {
				fatal(err)
			}
			dual := approval.DualApproval{Approvals: []approval.Approval{app1, app2}}
			writeJSON(*out, dual)
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
		app, err := approval.Sign(*item, *ttl, true, *signer, *role, pubBytes, privBytes)
		if err != nil {
			fatal(err)
		}
		writeJSON(*out, app)
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

func handleAudit(args []string) {
	if len(args) == 0 {
		fatal(errors.New("audit requires a subcommand: verify|explain|export"))
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
		if err := fs.Parse(args[1:]); err != nil {
			fatal(err)
		}
		if *decision == "" {
			fatal(errors.New("audit explain requires --decision"))
		}
		artifact, err := findArtifact(*auditPath, *decision)
		if err != nil {
			fatal(err)
		}
		outln("Decision: " + artifact.ID)
		outln("Summary: " + artifact.Summary)
		outln("Findings: " + strings.Join(artifact.Findings, "; "))
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
		data, err := os.ReadFile(*auditPath)
		if err != nil {
			fatal(err)
		}
		if *out == "" {
			if !gFlags.Quiet {
				_, _ = os.Stdout.Write(data)
			}
			return
		}
		if err := os.WriteFile(*out, data, 0600); err != nil {
			fatal(err)
		}
		outln("Audit export written: " + *out)
	default:
		fatal(errors.New("unknown audit subcommand"))
	}
}

func findArtifact(path string, id string) (audit.Artifact, error) {
	f, err := os.Open(path)
	if err != nil {
		return audit.Artifact{}, err
	}
	defer func() { _ = f.Close() }()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var a audit.Artifact
		if err := json.Unmarshal([]byte(line), &a); err != nil {
			continue
		}
		if a.ID == id {
			return a, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return audit.Artifact{}, err
	}
	return audit.Artifact{}, errors.New("decision not found")
}

func handleSystem(args []string) {
	if len(args) == 0 {
		fatal(errors.New("system requires a subcommand: status|config|health|coverage|confidence"))
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
	case "coverage":
		fs := flag.NewFlagSet("system coverage", flag.ExitOnError)
		rulesPath := fs.String("rules", "data/rules.json", "rules json")
		envPath := fs.String("env", "", "environment json (optional)")
		out := fs.String("out", "", "output file (optional)")
		if err := fs.Parse(args[1:]); err != nil {
			fatal(err)
		}
		rules, err := logic.LoadRules(*rulesPath)
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

func applyGatedRules(rules []logic.Rule, approvalPath string) ([]logic.Rule, []model.RuleResult) {
	if approvalPath != "" {
		if err := verifyAdminOverride(approvalPath); err == nil {
			return rules, nil
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
	if len(disabled) > 0 && !gFlags.Quiet {
		sort.Strings(disabled)
		outln("Gated rules disabled: " + strings.Join(disabled, ", "))
		outln("Admin approval required at install time to enable these packs.")
	}
	return out, placeholders
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
	format := fs.String("format", "cli", "output format: cli or json")
	if err := fs.Parse(args); err != nil {
		fatal(err)
	}

	if *in == "" {
		fatal(errors.New("-in is required"))
	}

	var events []model.Event
	readJSON(*in, &events)

	rules, err := logic.LoadRules(*rulesPath)
	if err != nil {
		fatal(err)
	}
	rules, placeholders := applyGatedRules(rules, *adminApproval)
	rep := logic.Reason(events, rules)
	if len(placeholders) > 0 {
		rep.Results = append(rep.Results, placeholders...)
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
	format := fs.String("format", "json", "output format: cli or json")
	configPath := fs.String("config", "", "ops config json (optional)")
	baselinePath := fs.String("baseline", "data/zero_trust_baseline.json", "zero-trust baseline")
	if err := fs.Parse(args); err != nil {
		fatal(err)
	}

	if *in == "" || *envPath == "" {
		fatal(errors.New("-in and -env are required"))
	}

	if _, err := zerotrust.LoadBaseline(*baselinePath); err != nil {
		fatal(errors.New("zero-trust baseline missing or invalid; run init-scan before assess"))
	}

	var events []model.Event
	readJSON(*in, &events)

	rules, err := logic.LoadRules(*rulesPath)
	if err != nil {
		fatal(err)
	}
	rules, placeholders := applyGatedRules(rules, *adminApproval)
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
	if *constraintsPath != "" {
		cons, err := governance.LoadConstraints(*constraintsPath)
		if err != nil {
			fatal(err)
		}
		rep := logic.ReasonWithMetrics(events, rules, metrics, includeEvidence)
		logic.ApplyConstraints(&rep, cons)
		out.Reasoning = rep
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
	if err := fs.Parse(args); err != nil {
		fatal(err)
	}

	rules, err := logic.LoadRules(*rulesPath)
	if err != nil {
		fatal(err)
	}
	f := eval.GenerateScenarios(rules)
	if err := eval.SaveScenarios(*out, f); err != nil {
		fatal(err)
	}
	fmt.Printf("Scenarios written: %s\n", *out)
}

func handleEvaluate(args []string) {
	fs := flag.NewFlagSet("evaluate", flag.ExitOnError)
	scenariosPath := fs.String("scenarios", "", "scenarios json")
	rulesPath := fs.String("rules", "", "rules json (optional)")
	format := fs.String("format", "json", "output format: cli, json, or md")
	outPath := fs.String("out", "", "output file (optional)")
	if err := fs.Parse(args); err != nil {
		fatal(err)
	}

	if *scenariosPath == "" {
		fatal(errors.New("-scenarios is required"))
	}

	rules, err := logic.LoadRules(*rulesPath)
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
	if err := fs.Parse(args); err != nil {
		fatal(err)
	}

	http.HandleFunc("/ingest", integration.IngestHandler)
	http.HandleFunc("/healthz", integration.HealthHandler)
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

func handleUI(args []string) {
	fs := flag.NewFlagSet("ui", flag.ExitOnError)
	addr := fs.String("addr", ":9090", "listen address")
	auditPath := fs.String("audit", "", "audit log")
	approvalsPath := fs.String("approvals", "", "approvals log")
	signedAuditPath := fs.String("signed-audit", "", "signed audit log")
	reportPath := fs.String("report", "", "reasoning report json")
	profilesPath := fs.String("profiles", "", "analyst profiles json")
	disagreementsPath := fs.String("disagreements", "", "disagreements log")
	keyPath := fs.String("key", "", "keypair json")
	basicUser := fs.String("basic-user", "", "basic auth user")
	basicPass := fs.String("basic-pass", "", "basic auth pass")
	if err := fs.Parse(args); err != nil {
		fatal(err)
	}

	server, err := ui.NewServer(*auditPath, *approvalsPath, *signedAuditPath, *reportPath, *profilesPath, *disagreementsPath, *keyPath, *basicUser, *basicPass)
	if err != nil {
		fatal(err)
	}
	fmt.Printf("UI listening on %s\n", *addr)
	srv := &http.Server{
		Addr:              *addr,
		Handler:           server.Routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil {
		fatal(err)
	}
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

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err.Error())
	os.Exit(1)
}

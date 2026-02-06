package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"aegisr/internal/approval"
	"aegisr/internal/audit"
	"aegisr/internal/core"
	"aegisr/internal/env"
	"aegisr/internal/eval"
	"aegisr/internal/governance"
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

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "generate":
		handleGenerate(os.Args[2:])
	case "reason":
		handleReason(os.Args[2:])
	case "assess":
		handleAssess(os.Args[2:])
	case "keys":
		handleKeys(os.Args[2:])
	case "approve":
		handleApprove(os.Args[2:])
	case "approve2":
		handleApprove2(os.Args[2:])
	case "verify":
		handleVerify(os.Args[2:])
	case "audit-verify":
		handleAuditVerify(os.Args[2:])
	case "audit-sign":
		handleAuditSign(os.Args[2:])
	case "generate-scenarios":
		handleGenerateScenarios(os.Args[2:])
	case "evaluate":
		handleEvaluate(os.Args[2:])
	case "ingest-http":
		handleIngestHTTP(os.Args[2:])
	case "ui":
		handleUI(os.Args[2:])
	case "init-scan":
		handleInitScan(os.Args[2:])
	case "scan":
		handleScan(os.Args[2:])
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Println("Aegis-R CLI")
	fmt.Println("Commands:")
	fmt.Println("  generate -out events.json -count 60 -seed 42")
	fmt.Println("  reason -in events.json [-approval approval.json] [-require-okta] [-rules rules.json] [-format cli|json]")
	fmt.Println("  assess -in events.json -env env.json -state state.json -audit audit.log [-rules rules.json] [-approval approval.json] [-policy policy.json] [-config ops.json] [-format cli|json] [-baseline data/zero_trust_baseline.json]")
	fmt.Println("  assess -in events.json -env env.json -state state.json -audit audit.log -siem siem.json (optional)")
	fmt.Println("  keys -out keypair.json")
	fmt.Println("  approve -key keypair.json -id change-1 -ttl 10m -okta true -signer alice -role approver -out approval.json")
	fmt.Println("  approve2 -key1 key1.json -key2 key2.json -id change-1 -ttl 10m -okta true -signer1 alice -signer2 bob -out dual_approval.json")
	fmt.Println("  verify -approval approval.json [-require-okta]")
	fmt.Println("  audit-verify -audit audit.log")
	fmt.Println("  audit-sign -audit audit.log -out signed_audit.log -signer soc-admin")
	fmt.Println("  generate-scenarios -out scenarios.json [-rules rules.json]")
	fmt.Println("  evaluate -scenarios scenarios.json [-rules rules.json]")
	fmt.Println("  ingest-http -addr :8080 (schema: ecs|elastic_ecs|ocsf|cim|splunk_cim_auth|splunk_cim_net|mde)")
	fmt.Println("  ui -addr :9090 -audit audit.log -signed-audit signed_audit.log -approvals approvals.log -report report.json -key keypair.json -basic-user user -basic-pass pass")
	fmt.Println("  init-scan -baseline data/zero_trust_baseline.json")
	fmt.Println("  scan -baseline data/zero_trust_baseline.json [-override-approval admin_approval.json]")
}

func handleGenerate(args []string) {
	fs := flag.NewFlagSet("generate", flag.ExitOnError)
	out := fs.String("out", "", "output file (default stdout)")
	count := fs.Int("count", 60, "number of events")
	seed := fs.Int64("seed", 0, "random seed")
	fs.Parse(args)

	events := sim.Synthetic(*seed, *count)
	writeJSON(*out, events)
}

func handleReason(args []string) {
	fs := flag.NewFlagSet("reason", flag.ExitOnError)
	in := fs.String("in", "", "input events json")
	approvalPath := fs.String("approval", "", "approval file")
	requireOkta := fs.Bool("require-okta", true, "require okta verified approvals")
	rulesPath := fs.String("rules", "", "rules json (optional)")
	format := fs.String("format", "cli", "output format: cli or json")
	fs.Parse(args)

	if *in == "" {
		fatal(errors.New("-in is required"))
	}

	var events []model.Event
	readJSON(*in, &events)

	rules, err := logic.LoadRules(*rulesPath)
	if err != nil {
		fatal(err)
	}
	rep := logic.Reason(events, rules)
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
	policyPath := fs.String("policy", "", "governance policy json (optional)")
	rulesPath := fs.String("rules", "", "rules json (optional)")
	format := fs.String("format", "json", "output format: cli or json")
	configPath := fs.String("config", "", "ops config json (optional)")
	baselinePath := fs.String("baseline", "data/zero_trust_baseline.json", "zero-trust baseline")
	fs.Parse(args)

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
	fs.Parse(args)

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
	fs.Parse(args)

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
	fs.Parse(args)

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
	fs.Parse(args)

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
	fs.Parse(args)
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
	fs.Parse(args)
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
	fs.Parse(args)

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
	format := fs.String("format", "json", "output format: cli or json")
	fs.Parse(args)

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
	default:
		fatal(errors.New("unknown format"))
	}
}

func handleIngestHTTP(args []string) {
	fs := flag.NewFlagSet("ingest-http", flag.ExitOnError)
	addr := fs.String("addr", ":8080", "listen address")
	fs.Parse(args)

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

func handleUI(args []string) {
	fs := flag.NewFlagSet("ui", flag.ExitOnError)
	addr := fs.String("addr", ":9090", "listen address")
	auditPath := fs.String("audit", "", "audit log")
	approvalsPath := fs.String("approvals", "", "approvals log")
	signedAuditPath := fs.String("signed-audit", "", "signed audit log")
	reportPath := fs.String("report", "", "reasoning report json")
	keyPath := fs.String("key", "", "keypair json")
	basicUser := fs.String("basic-user", "", "basic auth user")
	basicPass := fs.String("basic-pass", "", "basic auth pass")
	fs.Parse(args)

	server, err := ui.NewServer(*auditPath, *approvalsPath, *signedAuditPath, *reportPath, *keyPath, *basicUser, *basicPass)
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
	fs.Parse(args)
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
	fs.Parse(args)

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

func readJSON(path string, out interface{}) {
	if !ops.IsSafePath(path) {
		fatal(os.ErrInvalid)
	}
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

func verifyApprovalFile(path string) error {
	return verifyApprovalFileWithReq(path, true)
}

func verifyApprovalFileWithReq(path string, requireOkta bool) error {
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

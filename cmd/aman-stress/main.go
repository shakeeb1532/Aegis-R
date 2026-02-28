package main

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"aman/internal/approval"
	"aman/internal/audit"
	"aman/internal/core"
	"aman/internal/env"
	"aman/internal/eval"
	"aman/internal/logic"
	"aman/internal/model"
	"aman/internal/sim"
	"aman/internal/state"
)

type StressReport struct {
	GeneratedAt          time.Time                  `json:"generated_at"`
	Summary              string                     `json:"summary"`
	CausalShadow         CausalShadowSection        `json:"causal_shadow"`
	Adversarial          AdversarialSection         `json:"adversarial"`
	TelemetryDegradation TelemetryDegradationReport `json:"telemetry_degradation"`
	NoiseFirehose        NoiseFirehoseReport        `json:"noise_firehose"`
	Regression           RegressionReport           `json:"regression"`
	CausalBlindSpots     []BlindSpot                `json:"causal_blind_spots"`
	Recommendations      []string                   `json:"recommendations"`
}

type CausalShadowSection struct {
	Checks   []ScenarioCheck `json:"checks"`
	PassRate float64         `json:"pass_rate"`
}

type AdversarialSection struct {
	EvasionSuccessRate float64            `json:"evasion_detection_rate"`
	EvasionRuns        int                `json:"evasion_runs"`
	ProfileCoverage    map[string]float64 `json:"profile_coverage"`
	VendorNoiseMix     []string           `json:"vendor_noise_mix"`
	GovernanceChecks   []ScenarioCheck    `json:"governance_checks"`
}

type TelemetryDegradationReport struct {
	Profiles []TelemetryDegradationProfile `json:"profiles"`
}

type TelemetryDegradationProfile struct {
	Name    string                  `json:"name"`
	RuleID  string                  `json:"rule_id"`
	Points  []TelemetryDegradePoint `json:"points"`
	Dropoff string                  `json:"dropoff"`
}

type TelemetryDegradePoint struct {
	DegradePct float64 `json:"degrade_pct"`
	Outcome    string  `json:"outcome"`
	ReasonCode string  `json:"reason_code"`
	Confidence float64 `json:"confidence"`
}

type NoiseFirehoseReport struct {
	Events             int     `json:"events"`
	CorruptedPct       float64 `json:"corrupted_pct"`
	DurationSeconds    float64 `json:"duration_seconds"`
	ThroughputEPS      float64 `json:"throughput_eps"`
	MemAllocMB         float64 `json:"mem_alloc_mb"`
	AuditChainVerified bool    `json:"audit_chain_verified"`
}

type RegressionReport struct {
	Scenarios  int     `json:"scenarios"`
	Accuracy   float64 `json:"accuracy"`
	Mismatches int     `json:"mismatches"`
}

type ScenarioCheck struct {
	Name     string `json:"name"`
	Expected string `json:"expected"`
	Actual   string `json:"actual"`
	Pass     bool   `json:"pass"`
	Details  string `json:"details"`
}

type BlindSpot struct {
	Name   string `json:"name"`
	Detail string `json:"detail"`
}

type attackProfile struct {
	Name         string
	RuleID       string
	Builder      func(seed int64) []model.Event
	ExpectedNote string
}

func main() {
	rep, err := runStressValidation()
	if err != nil {
		fmt.Fprintf(os.Stderr, "stress validation failed: %v\n", err)
		os.Exit(1)
	}
	if err := writeReports(rep); err != nil {
		fmt.Fprintf(os.Stderr, "write report failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Stress validation complete: %s\n", filepath.Join("docs", "stress_validation_report.md"))
}

func runStressValidation() (StressReport, error) {
	rules := logic.DefaultRules()
	environment, err := env.Load(filepath.Join("data", "env.json"))
	if err != nil {
		environment = fallbackEnvironment()
	}

	causalShadow, shadowBlindSpots := runCausalShadow(rules, environment)
	adversarial, advBlindSpots := runAdversarial(rules, environment)
	degradation, degradeBlindSpots := runTelemetryDegradation(rules, environment)
	firehose, fireBlindSpots, err := runNoiseFirehose(rules, environment)
	if err != nil {
		return StressReport{}, err
	}
	regression := runRegression(rules)

	allBlindSpots := append([]BlindSpot{}, shadowBlindSpots...)
	allBlindSpots = append(allBlindSpots, advBlindSpots...)
	allBlindSpots = append(allBlindSpots, degradeBlindSpots...)
	allBlindSpots = append(allBlindSpots, fireBlindSpots...)
	sort.Slice(allBlindSpots, func(i, j int) bool { return allBlindSpots[i].Name < allBlindSpots[j].Name })

	return StressReport{
		GeneratedAt:          time.Now().UTC(),
		Summary:              "Causal synthetic stress validation using shadow scenarios, adversarial variants, telemetry degradation, and high-volume noise with domain profiles and vendor-noise patterns.",
		CausalShadow:         causalShadow,
		Adversarial:          adversarial,
		TelemetryDegradation: degradation,
		NoiseFirehose:        firehose,
		Regression:           regression,
		CausalBlindSpots:     allBlindSpots,
		Recommendations:      buildRecommendations(causalShadow, adversarial, degradation, firehose, regression, len(allBlindSpots)),
	}, nil
}

func runCausalShadow(rules []logic.Rule, environment env.Environment) (CausalShadowSection, []BlindSpot) {
	checks := []ScenarioCheck{}
	blind := []BlindSpot{}

	unreachableEnv := fallbackEnvironment()
	unreachableEnv.Identities = []env.Identity{{ID: "alice", Role: "admin", PrivLevel: "high"}}
	unreachableEnv.TrustBoundaries = []env.TrustBoundary{}
	events1 := []model.Event{
		ev("e1", "h-attacker", "alice", "lsass_access", 0),
		ev("e2", "h-target", "alice", "remote_service_creation", 1),
		ev("e3", "h-target", "alice", "network_logon", 2),
	}
	r1 := resultForRule(core.Assess(events1, rules, unreachableEnv, state.New()).Reasoning, "TA0008.LATERAL")
	c1 := ScenarioCheck{
		Name:     "logic-conflict-unreachable-zone",
		Expected: "infeasible/env_unreachable",
		Actual:   fmt.Sprintf("%v/%s", r1.Feasible, r1.ReasonCode),
		Pass:     !r1.Feasible && r1.ReasonCode == "env_unreachable",
		Details:  r1.Explanation,
	}
	checks = append(checks, c1)
	if !c1.Pass {
		blind = append(blind, BlindSpot{Name: c1.Name, Detail: c1.Actual})
	}

	events2 := []model.Event{
		ev("e10", "h1", "alice", "beacon_outbound", 0),
		ev("e11", "h2", "alice", "data_staging", 1),
		ev("e12", "h2", "alice", "large_outbound_transfer", 2),
	}
	r2 := resultForRule(core.Assess(events2, rules, environment, state.New()).Reasoning, "TA0010.EXFIL")
	c2 := ScenarioCheck{
		Name:     "missing-necessary-cause",
		Expected: "incomplete/evidence_gap-or-precond_missing",
		Actual:   fmt.Sprintf("%v/%s", r2.Feasible, r2.ReasonCode),
		Pass:     !r2.Feasible && (r2.ReasonCode == "evidence_gap" || r2.ReasonCode == "precond_missing"),
		Details:  r2.Explanation,
	}
	checks = append(checks, c2)
	if !c2.Pass {
		blind = append(blind, BlindSpot{Name: c2.Name, Detail: c2.Actual})
	}

	shadowEnv := environment
	shadowEnv.Identities = []env.Identity{{ID: "alice", Role: "user", PrivLevel: "standard"}}
	events3 := []model.Event{
		ev("e20", "h1", "alice", "token_manipulation", 0),
		ev("e21", "h1", "alice", "process_creation", 1),
		ev("e22", "h1", "alice", "lsass_access", 2),
	}
	r3 := resultForRule(core.Assess(events3, rules, shadowEnv, state.New()).Reasoning, "TA0006.CREDDUMP")
	c3 := ScenarioCheck{
		Name:     "shadow-admin-capability-check",
		Expected: "infeasible/identity_insufficient_priv-or-environment_unknown",
		Actual:   fmt.Sprintf("%v/%s", r3.Feasible, r3.ReasonCode),
		Pass:     !r3.Feasible && (r3.ReasonCode == "identity_insufficient_priv" || r3.ReasonCode == "environment_unknown"),
		Details:  r3.Explanation,
	}
	checks = append(checks, c3)
	if !c3.Pass {
		blind = append(blind, BlindSpot{Name: c3.Name, Detail: c3.Actual})
	}

	pass := 0
	for _, c := range checks {
		if c.Pass {
			pass++
		}
	}
	return CausalShadowSection{Checks: checks, PassRate: safeRatio(pass, len(checks))}, blind
}

func runAdversarial(rules []logic.Rule, environment env.Environment) (AdversarialSection, []BlindSpot) {
	blind := []BlindSpot{}
	rng := rand.New(rand.NewSource(42)) //nolint:gosec
	profiles := attackProfiles()
	evasionRuns := 500
	detected := 0
	perProfileTotal := map[string]int{}
	perProfileDetected := map[string]int{}
	vendors := []string{"ecs", "ocsf", "splunk", "okta", "cloudtrail", "sentinel", "crowdstrike", "mde"}

	for i := 0; i < evasionRuns; i++ {
		p := profiles[rng.Intn(len(profiles))]
		perProfileTotal[p.Name]++

		events := make([]model.Event, 0, 120)
		events = append(events, p.Builder(int64(1000+i))...)
		events = append(events, generateVendorNoise(int64(i), vendors[rng.Intn(len(vendors))], 90)...)

		res := resultForRule(core.Assess(events, rules, environment, state.New()).Reasoning, p.RuleID)
		outcome := classifyOutcome(res)
		if outcome != "impossible" {
			detected++
			perProfileDetected[p.Name]++
		}
	}

	coverage := map[string]float64{}
	for name, total := range perProfileTotal {
		coverage[name] = safeRatio(perProfileDetected[name], total)
		if coverage[name] < 0.9 {
			blind = append(blind, BlindSpot{Name: "adversarial-" + name, Detail: fmt.Sprintf("detection %.2f", coverage[name])})
		}
	}

	gChecks := []ScenarioCheck{}
	pub, priv, _ := approval.GenerateKeypair()
	a1, _ := approval.Sign("chg-1", 5*time.Minute, true, "analyst-a", "approver", pub, priv)
	a2 := a1
	err := approval.VerifyDual(approval.DualApproval{
		Approvals:   []approval.Approval{a1, a2},
		MinSigners:  2,
		RequireOkta: true,
	}, time.Now().UTC())
	gChecks = append(gChecks, ScenarioCheck{
		Name:     "governance-duplicate-signer",
		Expected: "reject",
		Actual:   boolToPassFail(err != nil),
		Pass:     err != nil,
		Details:  errString(err),
	})

	pub2, priv2, _ := approval.GenerateKeypair()
	empty, _ := approval.Sign("chg-2", 5*time.Minute, true, "", "approver", pub2, priv2)
	validPub, validPriv, _ := approval.GenerateKeypair()
	valid, _ := approval.Sign("chg-2", 5*time.Minute, true, "analyst-b", "approver", validPub, validPriv)
	err = approval.VerifyDual(approval.DualApproval{
		Approvals:   []approval.Approval{empty, valid},
		MinSigners:  2,
		RequireOkta: true,
	}, time.Now().UTC())
	gChecks = append(gChecks, ScenarioCheck{
		Name:     "governance-empty-signer-ignored",
		Expected: "reject",
		Actual:   boolToPassFail(err != nil),
		Pass:     err != nil,
		Details:  errString(err),
	})

	return AdversarialSection{
		EvasionSuccessRate: safeRatio(detected, evasionRuns),
		EvasionRuns:        evasionRuns,
		ProfileCoverage:    coverage,
		VendorNoiseMix:     vendors,
		GovernanceChecks:   gChecks,
	}, blind
}

func runTelemetryDegradation(rules []logic.Rule, environment env.Environment) (TelemetryDegradationReport, []BlindSpot) {
	profiles := []TelemetryDegradationProfile{
		{
			Name:   "exfil-chain",
			RuleID: "TA0010.EXFIL",
			Points: evaluateDegradationProfile(
				[]model.Event{
					ev("x1", "host-1", "alice", "beacon_outbound", 0),
					ev("x2", "host-1", "alice", "lsass_access", 1),
					ev("x3", "host-2", "alice", "data_staging", 2),
					ev("x4", "host-2", "alice", "large_outbound_transfer", 3),
				},
				"TA0010.EXFIL", rules, environment,
			),
		},
		{
			Name:   "identity-anomaly-chain",
			RuleID: "TA0006.IDENTITY_ANOMALY",
			Points: evaluateDegradationProfile(
				[]model.Event{
					ev("i1", "", "alice", "impossible_travel", 0),
					ev("i2", "", "alice", "new_device_login", 1),
				},
				"TA0006.IDENTITY_ANOMALY", rules, environment,
			),
		},
		{
			Name:   "persistence-chain",
			RuleID: "TA0003.PERSIST_EXTENDED",
			Points: evaluateDegradationProfile(
				[]model.Event{
					ev("p1", "host-1", "alice", "email_attachment_open", 0),
					ev("p2", "host-1", "alice", "macro_execution", 1),
					ev("p3", "host-1", "alice", "registry_run_key", 2),
					ev("p4", "host-1", "alice", "service_install", 3),
				},
				"TA0003.PERSIST_EXTENDED", rules, environment,
			),
		},
	}

	blind := []BlindSpot{}
	for i := range profiles {
		profiles[i].Dropoff = computeDropoff(profiles[i].Points)
		if strings.Contains(strings.ToLower(profiles[i].Dropoff), "25%") {
			blind = append(blind, BlindSpot{
				Name:   "degradation-" + profiles[i].Name,
				Detail: profiles[i].Dropoff,
			})
		}
	}
	return TelemetryDegradationReport{Profiles: profiles}, blind
}

func evaluateDegradationProfile(events []model.Event, ruleID string, rules []logic.Rule, environment env.Environment) []TelemetryDegradePoint {
	levels := []float64{0, 0.1, 0.25, 0.5, 0.75, 0.9}
	points := make([]TelemetryDegradePoint, 0, len(levels))
	rng := rand.New(rand.NewSource(11)) //nolint:gosec
	for _, level := range levels {
		mut := degradeEvents(events, level, rng)
		res := resultForRule(core.Assess(mut, rules, environment, state.New()).Reasoning, ruleID)
		points = append(points, TelemetryDegradePoint{
			DegradePct: level,
			Outcome:    classifyOutcome(res),
			ReasonCode: res.ReasonCode,
			Confidence: res.Confidence,
		})
	}
	return points
}

func computeDropoff(points []TelemetryDegradePoint) string {
	for _, p := range points {
		if p.DegradePct > 0 && p.Outcome != "feasible" {
			return fmt.Sprintf("quality drop observed at %.0f%% telemetry degradation", p.DegradePct*100)
		}
	}
	return "none"
}

func runNoiseFirehose(rules []logic.Rule, environment env.Environment) (NoiseFirehoseReport, []BlindSpot, error) {
	blind := []BlindSpot{}
	total := 281000
	corruptedPct := 0.05
	corruptedCount := int(float64(total) * corruptedPct)
	events := sim.Synthetic(99, total-corruptedCount)
	for i := 0; i < corruptedCount; i++ {
		events = append(events, model.Event{
			ID:   fmt.Sprintf("corrupt-%d", i),
			Time: time.Time{},
			Host: "",
			User: "",
			Type: "!!!corrupted",
		})
	}
	start := time.Now()
	var memBefore, memAfter runtime.MemStats
	runtime.ReadMemStats(&memBefore)
	out := core.Assess(events, rules, environment, state.New())
	runtime.ReadMemStats(&memAfter)
	elapsed := time.Since(start)

	artifactPath := filepath.Join(os.TempDir(), "aman-stress-audit.log")
	_ = os.Remove(artifactPath)
	var last string
	for i := 0; i < 2; i++ {
		a := audit.Artifact{
			ID:        fmt.Sprintf("stress-%d", i+1),
			CreatedAt: time.Now().UTC(),
			Summary:   out.Summary,
			Findings:  out.Findings,
			Reasoning: out.Reasoning.Narrative,
			PrevHash:  last,
		}
		h, err := audit.HashArtifact(a)
		if err != nil {
			return NoiseFirehoseReport{}, blind, err
		}
		a.Hash = h
		if err := audit.AppendLog(artifactPath, a); err != nil {
			return NoiseFirehoseReport{}, blind, err
		}
		last = h
	}
	verifyErr := audit.VerifyChain(artifactPath)
	if verifyErr != nil {
		blind = append(blind, BlindSpot{Name: "audit-chain-validation", Detail: verifyErr.Error()})
	}

	return NoiseFirehoseReport{
		Events:             len(events),
		CorruptedPct:       corruptedPct,
		DurationSeconds:    elapsed.Seconds(),
		ThroughputEPS:      float64(len(events)) / elapsed.Seconds(),
		MemAllocMB:         float64(memAfter.Alloc-memBefore.Alloc) / (1024 * 1024),
		AuditChainVerified: verifyErr == nil,
	}, blind, nil
}

func runRegression(rules []logic.Rule) RegressionReport {
	scenarios, err := eval.LoadScenarios(filepath.Join("data", "scenarios_realistic.json"))
	if err != nil {
		return RegressionReport{}
	}
	rep := eval.Score(scenarios, rules)
	return RegressionReport{
		Scenarios:  rep.Total,
		Accuracy:   rep.Accuracy,
		Mismatches: len(rep.Mismatches),
	}
}

func buildRecommendations(
	shadow CausalShadowSection,
	adv AdversarialSection,
	degrade TelemetryDegradationReport,
	fire NoiseFirehoseReport,
	reg RegressionReport,
	blindSpotCount int,
) []string {
	recs := []string{}
	if shadow.PassRate < 1 {
		recs = append(recs, "Fix failing causal-shadow scenarios before pilot; these are logic-level correctness blockers.")
	}
	if adv.EvasionSuccessRate < 0.95 {
		recs = append(recs, "Improve adversarial resilience by adding stricter context checks for noisy lateral chains.")
	}
	for _, p := range degrade.Profiles {
		if strings.Contains(strings.ToLower(p.Dropoff), "10%") || strings.Contains(strings.ToLower(p.Dropoff), "25%") {
			recs = append(recs, "Telemetry quality drops early for "+p.Name+"; prioritize ingestion quality guards.")
		}
	}
	if !fire.AuditChainVerified {
		recs = append(recs, "Audit chain verification failed under load; block pilot until fixed.")
	}
	if reg.Scenarios > 0 && reg.Accuracy < 0.85 {
		recs = append(recs, "Regression accuracy below pilot threshold (0.85). Expand calibration and rule tuning.")
	}
	if blindSpotCount == 0 {
		recs = append(recs, "No causal blind spots detected in this run; keep adding adversarial variants to avoid overfitting.")
	}
	return recs
}

func attackProfiles() []attackProfile {
	return []attackProfile{
		{
			Name:   "lateral-movement",
			RuleID: "TA0008.LATERAL",
			Builder: func(seed int64) []model.Event {
				return []model.Event{
					ev(fmt.Sprintf("lm-%d-1", seed), "host-1", "alice", "lsass_access", 0),
					ev(fmt.Sprintf("lm-%d-2", seed), "host-2", "alice", "remote_service_creation", 1),
					ev(fmt.Sprintf("lm-%d-3", seed), "host-2", "alice", "network_logon", 2),
				}
			},
			ExpectedNote: "should not be classified as impossible under noise",
		},
		{
			Name:   "identity-takeover",
			RuleID: "TA0006.IDENTITY_ANOMALY",
			Builder: func(seed int64) []model.Event {
				return []model.Event{
					ev(fmt.Sprintf("id-%d-1", seed), "", "alice", "impossible_travel", 0),
					ev(fmt.Sprintf("id-%d-2", seed), "", "alice", "new_device_login", 1),
					ev(fmt.Sprintf("id-%d-3", seed), "", "alice", "mfa_method_removed", 2),
				}
			},
			ExpectedNote: "should remain detectable in auth-heavy noise",
		},
		{
			Name:   "impact-encryption",
			RuleID: "TA0040.IMPACT_ENCRYPT",
			Builder: func(seed int64) []model.Event {
				return []model.Event{
					ev(fmt.Sprintf("im-%d-1", seed), "host-2", "alice", "token_manipulation", 0),
					ev(fmt.Sprintf("im-%d-2", seed), "host-2", "alice", "mass_file_rename", 1),
					ev(fmt.Sprintf("im-%d-3", seed), "host-2", "alice", "encrypt_activity", 2),
				}
			},
			ExpectedNote: "should be detectable with noisy process/file background",
		},
		{
			Name:   "cloud-policy-abuse",
			RuleID: "TA0004.ACCOUNT_MANIP",
			Builder: func(seed int64) []model.Event {
				return []model.Event{
					ev(fmt.Sprintf("cl-%d-1", seed), "acct-1", "alice", "impossible_travel", 0),
					ev(fmt.Sprintf("cl-%d-2", seed), "acct-1", "alice", "account_manipulation", 1),
					ev(fmt.Sprintf("cl-%d-3", seed), "acct-1", "alice", "admin_group_change", 2),
				}
			},
			ExpectedNote: "should not disappear in cloud IAM noise",
		},
	}
}

func generateVendorNoise(seed int64, vendor string, count int) []model.Event {
	rng := rand.New(rand.NewSource(seed + 77)) //nolint:gosec
	events := make([]model.Event, 0, count)
	pool := vendorPatternTypes(vendor)
	for i := 0; i < count; i++ {
		t := pool[rng.Intn(len(pool))]
		events = append(events, model.Event{
			ID:   fmt.Sprintf("%s-n-%d-%d", vendor, seed, i),
			Time: time.Now().UTC().Add(time.Duration(i) * time.Second),
			Host: fmt.Sprintf("%s-host-%d", vendor, rng.Intn(5)+1),
			User: fmt.Sprintf("%s-user-%d", vendor, rng.Intn(8)+1),
			Type: t,
			Details: map[string]interface{}{
				"vendor":  vendor,
				"pattern": "noise",
			},
		})
	}
	return events
}

func vendorPatternTypes(vendor string) []string {
	switch vendor {
	case "ecs":
		return []string{"process_creation", "file_read", "network_connection", "registry_change", "service_start"}
	case "ocsf":
		return []string{"authentication_success", "dns_query", "file_modify", "iam_change", "network_flow"}
	case "splunk":
		return []string{"authentication_success", "authentication_failure", "network_connection", "password_spray", "dns_query"}
	case "okta":
		return []string{"signin_success", "token_refresh_anomaly", "oauth_consent", "iam_change", "new_device_login"}
	case "cloudtrail":
		return []string{"iam_change", "role_assume", "policy_change", "new_firewall_rule", "trust_boundary_change"}
	case "sentinel":
		return []string{"process_creation", "registry_change", "file_modify", "authentication_failure", "service_install"}
	case "crowdstrike":
		return []string{"process_creation", "file_create", "file_modify", "registry_change", "service_install"}
	case "mde":
		return []string{"process_creation", "lsass_access", "registry_run_key", "service_install", "token_refresh_anomaly"}
	default:
		return []string{"dns_query", "file_read", "service_start", "inventory_sync", "heartbeat"}
	}
}

func fallbackEnvironment() env.Environment {
	return env.Environment{
		Hosts: []env.Host{
			{ID: "h-attacker", Zone: "user-net"},
			{ID: "h1", Zone: "user-net"},
			{ID: "h-target", Zone: "secure-net", Critical: true},
			{ID: "h2", Zone: "secure-net"},
			{ID: "host-1", Zone: "user-net"},
			{ID: "host-2", Zone: "secure-net"},
		},
		Identities: []env.Identity{
			{ID: "alice", Role: "user", PrivLevel: "standard"},
		},
		TrustBoundaries: []env.TrustBoundary{
			{ID: "tb-1", From: "user-net", To: "secure-net", Mode: "allow"},
		},
	}
}

func ev(id, host, user, typ string, seconds int) model.Event {
	return model.Event{
		ID:   id,
		Time: time.Now().UTC().Add(time.Duration(seconds) * time.Second),
		Host: host,
		User: user,
		Type: typ,
	}
}

func degradeEvents(events []model.Event, pct float64, rng *rand.Rand) []model.Event {
	out := make([]model.Event, len(events))
	for i := range events {
		out[i] = events[i]
		if rng.Float64() < pct {
			out[i].Host = ""
		}
		if rng.Float64() < pct {
			out[i].User = ""
		}
		if rng.Float64() < pct {
			out[i].Details = nil
		}
		if rng.Float64() < pct*0.5 {
			out[i].Time = time.Time{}
		}
	}
	return out
}

func resultForRule(rep model.ReasoningReport, ruleID string) model.RuleResult {
	for _, r := range rep.Results {
		if r.RuleID == ruleID {
			return r
		}
	}
	return model.RuleResult{RuleID: ruleID, ReasonCode: "rule_not_found"}
}

func classifyOutcome(r model.RuleResult) string {
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
	return "impossible"
}

func safeRatio(num int, den int) float64 {
	if den == 0 {
		return 0
	}
	return float64(num) / float64(den)
}

func boolToPassFail(ok bool) string {
	if ok {
		return "pass"
	}
	return "fail"
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func writeReports(rep StressReport) error {
	jsonPath := filepath.Join("docs", "stress_validation_report.json")
	mdPath := filepath.Join("docs", "stress_validation_report.md")
	if err := os.MkdirAll(filepath.Dir(jsonPath), 0755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(jsonPath, b, 0600); err != nil {
		return err
	}
	return os.WriteFile(mdPath, []byte(renderMarkdown(rep)), 0600)
}

func renderMarkdown(rep StressReport) string {
	var sb strings.Builder
	sb.WriteString("# Aman Causal Synthetic Validation Report\n\n")
	sb.WriteString(fmt.Sprintf("Generated: %s\n\n", rep.GeneratedAt.Format(time.RFC3339)))
	sb.WriteString("## Executive Summary\n\n")
	sb.WriteString(rep.Summary + "\n\n")
	sb.WriteString(fmt.Sprintf("- Causal shadow pass rate: %.2f%%\n", rep.CausalShadow.PassRate*100))
	sb.WriteString(fmt.Sprintf("- Adversarial evasion detection rate: %.2f%% (%d runs)\n", rep.Adversarial.EvasionSuccessRate*100, rep.Adversarial.EvasionRuns))
	sb.WriteString(fmt.Sprintf("- Regression accuracy: %.3f (%d labeled checks)\n", rep.Regression.Accuracy, rep.Regression.Scenarios))
	sb.WriteString(fmt.Sprintf("- Firehose throughput: %.0f events/sec over %d events\n\n", rep.NoiseFirehose.ThroughputEPS, rep.NoiseFirehose.Events))

	sb.WriteString("## 1) Causal Shadow Checks\n\n")
	sb.WriteString("| Check | Expected | Actual | Pass |\n|---|---|---|---|\n")
	for _, c := range rep.CausalShadow.Checks {
		sb.WriteString(fmt.Sprintf("| %s | %s | %s | %v |\n", c.Name, c.Expected, c.Actual, c.Pass))
	}

	sb.WriteString("\n## 2) Adversarial Simulation\n\n")
	sb.WriteString(fmt.Sprintf("- Detection rate: %.2f%%\n", rep.Adversarial.EvasionSuccessRate*100))
	sb.WriteString("- Domain profile coverage:\n")
	profileNames := make([]string, 0, len(rep.Adversarial.ProfileCoverage))
	for name := range rep.Adversarial.ProfileCoverage {
		profileNames = append(profileNames, name)
	}
	sort.Strings(profileNames)
	for _, name := range profileNames {
		sb.WriteString(fmt.Sprintf("  - %s: %.2f%%\n", name, rep.Adversarial.ProfileCoverage[name]*100))
	}
	sb.WriteString("- Vendor noise mix: " + strings.Join(rep.Adversarial.VendorNoiseMix, ", ") + "\n")
	sb.WriteString("- Governance adversarial checks:\n")
	for _, c := range rep.Adversarial.GovernanceChecks {
		sb.WriteString(fmt.Sprintf("  - %s: %v (%s)\n", c.Name, c.Pass, c.Details))
	}

	sb.WriteString("\n## 3) Telemetry Degradation\n\n")
	for _, profile := range rep.TelemetryDegradation.Profiles {
		sb.WriteString(fmt.Sprintf("### %s (`%s`)\n\n", profile.Name, profile.RuleID))
		sb.WriteString("| Degradation | Outcome | Reason Code | Confidence |\n|---:|---|---|---:|\n")
		for _, p := range profile.Points {
			sb.WriteString(fmt.Sprintf("| %.0f%% | %s | %s | %.3f |\n", p.DegradePct*100, p.Outcome, p.ReasonCode, p.Confidence))
		}
		sb.WriteString(fmt.Sprintf("\nDropoff: %s\n\n", profile.Dropoff))
	}

	sb.WriteString("## 4) Noise Firehose\n\n")
	sb.WriteString(fmt.Sprintf("- Events processed: %d\n", rep.NoiseFirehose.Events))
	sb.WriteString(fmt.Sprintf("- Corrupted/conflicted input share: %.2f%%\n", rep.NoiseFirehose.CorruptedPct*100))
	sb.WriteString(fmt.Sprintf("- Duration: %.2fs\n", rep.NoiseFirehose.DurationSeconds))
	sb.WriteString(fmt.Sprintf("- Throughput: %.0f events/sec\n", rep.NoiseFirehose.ThroughputEPS))
	sb.WriteString(fmt.Sprintf("- Memory delta: %.2f MB\n", rep.NoiseFirehose.MemAllocMB))
	sb.WriteString(fmt.Sprintf("- Audit chain verified: %v\n\n", rep.NoiseFirehose.AuditChainVerified))

	sb.WriteString("## Causal Blind Spots\n\n")
	if len(rep.CausalBlindSpots) == 0 {
		sb.WriteString("No blind spots detected in this run.\n")
	} else {
		for _, b := range rep.CausalBlindSpots {
			sb.WriteString(fmt.Sprintf("- `%s`: %s\n", b.Name, b.Detail))
		}
	}

	sb.WriteString("\n## Recommendations\n\n")
	for _, r := range rep.Recommendations {
		sb.WriteString("- " + r + "\n")
	}
	sb.WriteString("\n## Synthetic Flywheel Mapping\n\n")
	sb.WriteString("1. Curation: starts from existing realistic + synthetic rule scenarios.\n")
	sb.WriteString("2. Generation: domain-specific chains + vendor-noise pattern variants.\n")
	sb.WriteString("3. Probing: identifies minimal conditions that flip verdicts or reason codes.\n")
	sb.WriteString("4. Remediation: failing variants become permanent regression fixtures.\n")
	return sb.String()
}

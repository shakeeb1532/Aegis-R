package logic

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"

	"aman/internal/governance"
	"aman/internal/model"
	"aman/internal/ops"
)

type Rule struct {
	ID                   string                      `json:"id"`
	Name                 string                      `json:"name"`
	Requirements         []model.EvidenceRequirement `json:"requirements"`
	Preconds             []string                    `json:"preconds"`
	PrecondGroups        [][]string                  `json:"precond_groups,omitempty"`
	Explain              string                      `json:"explain"`
	Contradictions       []string                    `json:"contradictions,omitempty"`
	RequiresContext      string                      `json:"requires_context,omitempty"` // "", "host", "identity"
	RequiresReachability *bool                       `json:"requires_reachability,omitempty"`
	RequiresHighPriv     *bool                       `json:"requires_high_priv,omitempty"`
	TargetEventTypes     []string                    `json:"target_event_types,omitempty"`
	Mitre                MitreMeta                   `json:"mitre"`
	Provenance           Provenance                  `json:"provenance"`
	Constraints          RuleConstraints             `json:"constraints"`
	NistCSF              []string                    `json:"nist_csf,omitempty"`
	KillChain            []string                    `json:"kill_chain,omitempty"`
}

type MitreMeta struct {
	Tactic    string   `json:"tactic"`
	Technique string   `json:"technique"`
	Subtech   string   `json:"subtechnique"`
	Links     []string `json:"links"`
}

type Provenance struct {
	Author     string   `json:"author"`
	Version    string   `json:"version"`
	Sources    []string `json:"sources"`
	ReviewedBy []string `json:"reviewed_by"`
	ApprovedAt string   `json:"approved_at"`
}

type RuleConstraints struct {
	MinConfidence float64  `json:"min_confidence"`
	AppliesTo     []string `json:"applies_to"`
}

var ruleResultPool = sync.Pool{
	New: func() any {
		return &model.RuleResult{}
	},
}

func DefaultRules() []Rule {
	if rules, err := loadEmbeddedDefaultRules(); err == nil && len(rules) > 0 {
		return rules
	}
	rules := []Rule{
		{
			ID:   "TA0001.PHISHING",
			Name: "Initial Access via Phishing",
			Requirements: []model.EvidenceRequirement{
				{Type: "email_attachment_open", Description: "User opened malicious attachment"},
				{Type: "macro_execution", Description: "Macro executed from attachment"},
				{Type: "beacon_outbound", Description: "Outbound beacon to known C2"},
			},
			Preconds: []string{},
			Explain:  "User interaction and macro execution leading to outbound beaconing.",
		},
		{
			ID:   "TA0006.CREDDUMP",
			Name: "Credential Dumping",
			Requirements: []model.EvidenceRequirement{
				{Type: "process_creation", Description: "Credential dumping tool execution"},
				{Type: "lsass_access", Description: "Access to LSASS"},
			},
			Preconds: []string{"privilege_escalation"},
			Explain:  "Requires elevated privileges to access credential stores.",
		},
		{
			ID:   "TA0008.LATERAL",
			Name: "Lateral Movement",
			Requirements: []model.EvidenceRequirement{
				{Type: "remote_service_creation", Description: "Remote service created"},
				{Type: "network_logon", Description: "Successful network logon"},
			},
			Preconds: []string{"credential_access"},
			Explain:  "Requires valid credentials before remote execution.",
		},
		{
			ID:   "TA0004.PRIVESCA",
			Name: "Privilege Escalation",
			Requirements: []model.EvidenceRequirement{
				{Type: "token_manipulation", Description: "Token manipulation activity"},
				{Type: "admin_group_change", Description: "User added to admin group"},
			},
			Preconds: []string{},
			Explain:  "Evidence of elevating access beyond initial privileges.",
		},
		{
			ID:   "TA0003.PERSIST",
			Name: "Persistence",
			Requirements: []model.EvidenceRequirement{
				{Type: "registry_run_key", Description: "Registry run key set"},
				{Type: "scheduled_task", Description: "Scheduled task created"},
			},
			Preconds: []string{"initial_access"},
			Explain:  "Persistence established after initial access.",
		},
		{
			ID:   "TA0011.C2",
			Name: "Command and Control",
			Requirements: []model.EvidenceRequirement{
				{Type: "beacon_outbound", Description: "Outbound beacon to known C2"},
				{Type: "dns_tunneling", Description: "DNS tunneling patterns"},
			},
			Preconds: []string{"initial_access"},
			Explain:  "C2 established after initial access.",
		},
		{
			ID:   "TA0010.EXFIL",
			Name: "Exfiltration",
			Requirements: []model.EvidenceRequirement{
				{Type: "data_staging", Description: "Data staged in archive"},
				{Type: "large_outbound_transfer", Description: "Large outbound data transfer"},
			},
			Preconds: []string{"c2_established", "credential_access"},
			Explain:  "Exfiltration typically follows C2 and credential access.",
		},
		{
			ID:   "TA0006.IDENTITY_ANOMALY",
			Name: "Identity Anomaly (Impossible Travel / New Device)",
			Requirements: []model.EvidenceRequirement{
				{Type: "impossible_travel", Description: "Login from distant geographies"},
				{Type: "new_device_login", Description: "New device or unknown client"},
			},
			Preconds: []string{},
			Explain:  "Identity anomalies indicate possible account compromise.",
		},
		{
			ID:   "TA0004.MFA_BYPASS",
			Name: "MFA Disable or Bypass",
			Requirements: []model.EvidenceRequirement{
				{Type: "mfa_method_removed", Description: "MFA method removed or reset"},
				{Type: "token_refresh_anomaly", Description: "Unusual token refresh or replay"},
			},
			Preconds: []string{"identity_compromise"},
			Explain:  "MFA changes combined with token anomalies indicate bypass.",
		},
		{
			ID:   "TA0002.LOLBIN_CHAIN",
			Name: "Suspicious LOLBin Execution Chain",
			Requirements: []model.EvidenceRequirement{
				{Type: "process_creation", Description: "Suspicious process creation"},
				{Type: "lolbin_execution", Description: "Known LOLBin executed (rundll32/mshta/certutil)"},
			},
			Preconds: []string{"initial_access"},
			Explain:  "LOLBin execution following initial access suggests hands-on-keyboard activity.",
		},
		{
			ID:   "TA0003.PERSIST_EXTENDED",
			Name: "Extended Persistence Mechanisms",
			Requirements: []model.EvidenceRequirement{
				{Type: "registry_run_key", Description: "Registry run key set"},
				{Type: "service_install", Description: "Service installed for persistence"},
			},
			Preconds: []string{"initial_access"},
			Explain:  "Persistence via registry and services after initial access.",
		},
		{
			ID:   "TA0006.VALID_ACCOUNTS",
			Name: "Valid Accounts Abuse",
			Requirements: []model.EvidenceRequirement{
				{Type: "signin_success", Description: "Sign-in using valid credentials in unusual context"},
				{Type: "new_device_login", Description: "New device or unknown client"},
			},
			Preconds: []string{},
			Explain:  "Compromised valid accounts enable access without malware.",
		},
		{
			ID:   "TA0006.BRUTE_FORCE",
			Name: "Brute Force / Credential Stuffing",
			Requirements: []model.EvidenceRequirement{
				{Type: "password_spray", Description: "Password spraying pattern detected"},
				{Type: "credential_stuffing", Description: "Credential stuffing pattern detected"},
			},
			Preconds: []string{},
			Explain:  "High-volume authentication failures followed by access attempts.",
		},
		{
			ID:   "TA0004.ACCOUNT_MANIP",
			Name: "Account Manipulation",
			Requirements: []model.EvidenceRequirement{
				{Type: "account_manipulation", Description: "Account permissions or credentials modified"},
				{Type: "admin_group_change", Description: "User added to privileged group"},
			},
			Preconds: []string{"identity_compromise"},
			Explain:  "Account changes used to persist or elevate access.",
		},
		{
			ID:   "TA0005.AUTH_PROCESS_MOD",
			Name: "Modify Authentication Process",
			Requirements: []model.EvidenceRequirement{
				{Type: "auth_process_modify", Description: "Authentication process modified"},
				{Type: "mfa_method_removed", Description: "MFA method removed or reset"},
			},
			Preconds: []string{"identity_compromise"},
			Explain:  "Authentication controls were altered to bypass access checks.",
		},
		{
			ID:   "TA0011.APP_LAYER_C2",
			Name: "Application Layer Protocol C2",
			Requirements: []model.EvidenceRequirement{
				{Type: "app_layer_c2", Description: "C2 over web/mail/DNS protocols"},
				{Type: "beacon_outbound", Description: "Outbound beaconing to known C2"},
			},
			Preconds: []string{"initial_access"},
			Explain:  "C2 over common application protocols for stealth.",
		},
		{
			ID:   "TA0005.IMPAIR_DEFENSES",
			Name: "Impair Defenses",
			Requirements: []model.EvidenceRequirement{
				{Type: "disable_logging", Description: "Security logging disabled or altered"},
				{Type: "cloud_firewall_change", Description: "Cloud firewall or security group opened"},
			},
			Preconds: []string{},
			Explain:  "Defensive controls weakened to evade detection.",
		},
		{
			ID:   "TA0010.EXFIL_WEB",
			Name: "Exfiltration Over Web Service",
			Requirements: []model.EvidenceRequirement{
				{Type: "exfil_web_service", Description: "Data exfil via web service"},
				{Type: "large_outbound_transfer", Description: "Large outbound data transfer"},
			},
			Preconds: []string{"c2_established"},
			Explain:  "Exfiltration using legitimate web services.",
		},
		{
			ID:   "TA0001.PHISH_LINK",
			Name: "Phishing via Link and OAuth Consent",
			Requirements: []model.EvidenceRequirement{
				{Type: "phish_link_click", Description: "User clicked phishing link"},
				{Type: "oauth_consent", Description: "OAuth consent granted to suspicious app"},
			},
			Preconds: []string{},
			Explain:  "Link phishing followed by OAuth consent indicates account compromise.",
		},
		{
			ID:   "TA0003.MAILBOX_PERSIST",
			Name: "Mailbox Rule Persistence",
			Requirements: []model.EvidenceRequirement{
				{Type: "mailbox_rule_create", Description: "Mailbox rule created"},
				{Type: "forwarding_rule_set", Description: "Auto-forwarding rule set"},
			},
			Preconds: []string{"signin_success"},
			Explain:  "Persistence through mailbox rules and forwarding.",
		},
		{
			ID:   "TA0040.IMPACT_ENCRYPT",
			Name: "Data Encrypted for Impact",
			Requirements: []model.EvidenceRequirement{
				{Type: "mass_file_rename", Description: "Mass file renaming"},
				{Type: "encrypt_activity", Description: "High-rate encryption activity"},
			},
			Preconds: []string{"privilege_escalation"},
			Explain:  "Encryption activity at scale indicates ransomware impact.",
		},
		{
			ID:   "TA0040.RECOVERY_INHIBIT",
			Name: "Inhibit System Recovery",
			Requirements: []model.EvidenceRequirement{
				{Type: "shadow_copy_delete", Description: "Shadow copies deleted"},
			},
			Preconds: []string{},
			Explain:  "Recovery features disabled to prevent restoration.",
		},
		{
			ID:   "TA0006.INSIDER_EXFIL",
			Name: "Insider Data Exfiltration",
			Requirements: []model.EvidenceRequirement{
				{Type: "bulk_download", Description: "Bulk download or data access"},
				{Type: "unusual_access_scope", Description: "Unusual access scope"},
			},
			Preconds: []string{"signin_success"},
			Explain:  "Large-scale access without compromise signals suggests insider misuse.",
		},
		{
			ID:   "TA0043.SUPPLY_CHAIN",
			Name: "Supply Chain Compromise",
			Requirements: []model.EvidenceRequirement{
				{Type: "ci_runner_compromise", Description: "CI runner compromise"},
				{Type: "artifact_tamper", Description: "Build artifact tampering"},
			},
			Preconds: []string{},
			Explain:  "Build pipeline compromise with artifact tampering.",
		},
		{
			ID:   "TA0008.CLOUD_PIVOT",
			Name: "Cloud Lateral Movement",
			Requirements: []model.EvidenceRequirement{
				{Type: "role_assume", Description: "Role assumed"},
				{Type: "trust_policy_change", Description: "Trust policy modified"},
			},
			Preconds: []string{},
			Explain:  "Cross-account pivot using trust policy changes.",
		},
		{
			ID:   "TA0004.SAAS_ADMIN",
			Name: "SaaS Admin Takeover",
			Requirements: []model.EvidenceRequirement{
				{Type: "new_admin_role", Description: "Admin role granted"},
				{Type: "oauth_app_grant", Description: "High-privilege OAuth grant"},
			},
			Preconds: []string{"identity_compromise"},
			Explain:  "Admin access gained through OAuth grants and role changes.",
		},
		{
			ID:   "TA0005.EVASION_C2",
			Name: "Network Evasion via Proxy/Tunnel",
			Requirements: []model.EvidenceRequirement{
				{Type: "domain_fronting", Description: "Domain fronting detected"},
				{Type: "tor_exit", Description: "TOR exit node traffic"},
				{Type: "dns_tunnel", Description: "DNS tunnel detected"},
			},
			Preconds: []string{"initial_access"},
			Explain:  "Evasive networking used to hide C2 channels.",
		},
		{
			ID:   "TA0005.LOG_TAMPER",
			Name: "Disable or Modify Security Logging",
			Requirements: []model.EvidenceRequirement{
				{Type: "disable_logging", Description: "Security logging disabled"},
				{Type: "policy_bypass", Description: "Control policy bypassed"},
			},
			Preconds: []string{"initial_access"},
			Explain:  "Disabling logging to hide attacker activity.",
		},
		{
			ID:   "TA0010.BULK_EXFIL",
			Name: "Bulk Data Exfiltration",
			Requirements: []model.EvidenceRequirement{
				{Type: "bulk_download", Description: "Bulk data access or download"},
				{Type: "large_outbound_transfer", Description: "Large outbound data transfer"},
			},
			Preconds: []string{"credential_access"},
			Explain:  "Bulk data access followed by outbound transfer.",
		},
		{
			ID:   "TA0008.ADMIN_PROTOCOL_LATERAL",
			Name: "Admin Protocol Lateral Movement",
			Requirements: []model.EvidenceRequirement{
				{Type: "new_inbound_admin_protocol", Description: "New inbound admin protocol used"},
				{Type: "network_logon", Description: "Successful network logon"},
			},
			Preconds: []string{"credential_access"},
			Explain:  "Lateral movement over admin protocols with valid credentials.",
		},
		{
			ID:   "TA0001.DEVICE_CODE_PHISH",
			Name: "Device Code Phishing",
			Requirements: []model.EvidenceRequirement{
				{Type: "device_code_flow_start", Description: "Device code flow initiated"},
				{Type: "device_code_flow_success", Description: "Device code flow completed"},
			},
			Preconds: []string{},
			Explain:  "Abuse of device code authentication flow indicates likely credential theft.",
		},
		{
			ID:   "TA0001.OAUTH_CONSENT_PHISH",
			Name: "OAuth Consent Phishing",
			Requirements: []model.EvidenceRequirement{
				{Type: "oauth_consent", Description: "OAuth consent granted"},
				{Type: "new_app_grant", Description: "New app grant with elevated scopes"},
			},
			Preconds: []string{},
			Explain:  "Malicious app consent grants attacker access tokens and persistent access.",
		},
		{
			ID:   "TA0001.DEVICE_JOIN_PHISH",
			Name: "Device Join Phishing",
			Requirements: []model.EvidenceRequirement{
				{Type: "device_join_request", Description: "Device join request initiated"},
				{Type: "device_join_complete", Description: "Device successfully joined/registered"},
			},
			Preconds: []string{},
			Explain:  "Phishing to register attacker-controlled device to tenant.",
		},
		{
			ID:   "TA0001.STOLEN_CREDS",
			Name: "Stolen Credentials Initial Access",
			Requirements: []model.EvidenceRequirement{
				{Type: "signin_success", Description: "Sign-in using valid credentials"},
				{Type: "token_reuse", Description: "Token reuse or session replay"},
			},
			Preconds: []string{},
			Explain:  "Stolen credentials used for initial access, often detected by token reuse.",
		},
		{
			ID:   "TA0001.STOLEN_CREDS_ANOMALY",
			Name: "Stolen Credentials with Anomalous Access",
			Requirements: []model.EvidenceRequirement{
				{Type: "signin_success", Description: "Sign-in using valid credentials"},
				{Type: "token_reuse", Description: "Token reuse or session replay"},
				{Type: "new_device_login", Description: "New device or unknown client"},
			},
			Preconds: []string{},
			Explain:  "Stolen credentials with anomalous device access indicate initial compromise.",
		},
	}
	normalizeRuleMetadata(rules)
	return rules
}

func LoadRules(path string) ([]Rule, error) {
	if path == "" {
		return DefaultRules(), nil
	}
	if !ops.IsSafePath(path) {
		return nil, fmt.Errorf("%w: %s", ErrInvalidRulePath, path)
	}
	//nolint:gosec // path validated via IsSafePath
	// #nosec G304
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rules []Rule
	if err := json.Unmarshal(data, &rules); err != nil {
		return nil, err
	}
	normalizeRuleMetadata(rules)
	if len(rules) == 0 {
		return nil, fmt.Errorf("%w: empty catalog", ErrInvalidRuleCatalog)
	}
	if err := ValidateRules(rules); err != nil {
		return nil, err
	}
	return rules, nil
}

func LoadRulesCombined(basePath string, extraPath string) ([]Rule, error) {
	base, err := LoadRules(basePath)
	if err != nil {
		return nil, err
	}
	if extraPath == "" {
		return base, nil
	}
	extra, err := LoadRules(extraPath)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	merged := make([]Rule, 0, len(base)+len(extra))
	for _, r := range base {
		if r.ID == "" {
			return nil, fmt.Errorf("%w: empty rule id in base rules", ErrInvalidRuleCatalog)
		}
		seen[r.ID] = true
		merged = append(merged, r)
	}
	for _, r := range extra {
		if r.ID == "" {
			return nil, fmt.Errorf("%w: empty rule id in extra rules", ErrInvalidRuleCatalog)
		}
		if seen[r.ID] {
			return nil, fmt.Errorf("%w: duplicate rule id %s", ErrInvalidRuleCatalog, r.ID)
		}
		seen[r.ID] = true
		merged = append(merged, r)
	}
	if err := ValidateRules(merged); err != nil {
		return nil, err
	}
	return merged, nil
}

func ValidateRules(rules []Rule) error {
	seen := map[string]bool{}
	for _, r := range rules {
		if r.ID == "" || r.Name == "" {
			return fmt.Errorf("%w: rule missing id or name", ErrInvalidRuleCatalog)
		}
		if seen[r.ID] {
			return fmt.Errorf("%w: duplicate rule id %s", ErrInvalidRuleCatalog, r.ID)
		}
		seen[r.ID] = true
		if len(r.Requirements) == 0 {
			return fmt.Errorf("%w: rule %s has no requirements", ErrInvalidRuleCatalog, r.ID)
		}
		if r.RequiresContext != "" && r.RequiresContext != "host" && r.RequiresContext != "identity" {
			return fmt.Errorf("%w: rule %s invalid requires_context %q", ErrInvalidRuleCatalog, r.ID, r.RequiresContext)
		}
		if r.Constraints.MinConfidence < 0 || r.Constraints.MinConfidence > 1 {
			return fmt.Errorf("%w: rule %s min_confidence out of range", ErrInvalidRuleCatalog, r.ID)
		}
	}
	return nil
}

func Reason(events []model.Event, rules []Rule) model.ReasoningReport {
	return ReasonWithMetrics(events, rules, nil, false)
}

func ReasonWithMetrics(events []model.Event, rules []Rule, metrics *ops.Metrics, includeEvidence bool) model.ReasoningReport {
	index := make(map[string][]int, 64)
	for i, e := range events {
		index[e.Type] = append(index[e.Type], i)
	}
	cfg := DefaultReasonerConfig()
	cfg = sanitizeReasonerConfig(cfg)
	now := cfg.Now()
	facts := deriveCausalFacts(events, index)

	results := make([]model.RuleResult, 0, len(rules))
	narrative := []string{}
	for _, rule := range rules {
		if metrics != nil {
			metrics.IncRules(1)
		}
		missing := make([]model.EvidenceRequirement, 0, len(rule.Requirements))
		totalMatches := 0
		for _, req := range rule.Requirements {
			totalMatches += len(index[req.Type])
		}
		var supporting []model.Event
		if includeEvidence && totalMatches > 0 {
			supporting = make([]model.Event, 0, totalMatches)
		}
		supportingIDs := make([]string, 0, totalMatches)
		for _, req := range rule.Requirements {
			idxs := index[req.Type]
			if len(idxs) == 0 {
				missing = append(missing, req)
				continue
			}
			for _, idx := range idxs {
				if includeEvidence {
					supporting = append(supporting, events[idx])
				}
				if events[idx].ID != "" {
					supportingIDs = append(supportingIDs, events[idx].ID)
				}
			}
		}
		precondOK := true
		requirementAt, hasReqTime := earliestRequirementTime(events, index, rule)
		missingPreconds := preconditionGaps(rule, facts, requirementAt, hasReqTime, cfg.OrderingJitter)
		orderAmbiguous := hasOrderAmbiguousPreconds(missingPreconds)
		if len(missingPreconds) > 0 {
			precondOK = false
		}
		highSignal := hasHighSignalEvidence(index)
		telemetryGap := len(missingPreconds) > 0 && highSignal
		contradiction := hasContradiction(rule, events, index)
		contextReq := contextForRule(rule)
		missingContext := false
		if contextReq != "" && !hasContext(events, index, contextReq) {
			missingContext = true
		}
		missing = append(missing, missingPreconds...)
		if missingContext {
			missing = append(missing, model.EvidenceRequirement{
				Type:        "environment_context",
				Description: "Required context not present for rule evaluation",
			})
		}
		causalFeasible, causalBlockers, necessaryCauses, necessaryCauseSets, causalErr := evaluateRuleCausally(
			rule,
			reqPresence(index, rule),
			precondStatusMap(rule, facts, requirementAt, hasReqTime, cfg.OrderingJitter),
			map[string]bool{
				"no_contradiction": true,
				"context_ok":       !missingContext,
				"env_reachable":    true,
				"identity_priv_ok": true,
			},
			cfg.CausalMaxSetSize,
		)
		feasible := causalFeasible
		causalErrMsg := ""
		if causalErr != nil {
			feasible = false
			causalErrMsg = causalErr.Error()
			missing = append(missing, model.EvidenceRequirement{
				Type:        "causal_model_error",
				Description: "Causal model evaluation failed",
			})
		}
		confidence, confidenceFactors := scoreConfidence(rule, supporting, missing, precondOK || telemetryGap, now, highSignal)
		if feasible && rule.Constraints.MinConfidence > 0 && confidence < rule.Constraints.MinConfidence {
			feasible = false
			missing = append(missing, model.EvidenceRequirement{
				Type:        "confidence_threshold",
				Description: "Confidence below rule minimum",
			})
		}
		name := rule.Name
		if contradiction {
			name = name + " (conflicted)"
		} else if telemetryGap {
			name = name + " (telemetry gap)"
		} else if orderAmbiguous {
			name = name + " (ordering ambiguous)"
		} else if !precondOK {
			name = name + " (preconditions unmet)"
		}
		reason := rule.Explain
		missingNames := []string{}
		if contradiction {
			missing = []model.EvidenceRequirement{}
			reason += " Contradictory evidence observed."
		} else if telemetryGap {
			reason += " High-signal defensive impairment suggests a telemetry gap."
		} else if orderAmbiguous {
			reason += " Ordering is ambiguous within the configured jitter window."
		} else if missingContext {
			reason += " Required context missing."
		} else if len(missing) > 0 {
			missingNames = requirementNames(missing)
			reason += " Missing evidence: " + strings.Join(missingNames, ", ")
		}
		gapNarrative := ""
		if contradiction {
			gapNarrative = "Conflicted: evidence contradicts a required condition for this attack path."
		} else if telemetryGap {
			gapNarrative = "High-signal defensive impairment suggests missing telemetry; treat as incomplete pending evidence."
		} else if orderAmbiguous {
			gapNarrative = "Event ordering is ambiguous within the jitter window; treat as incomplete until ordering is confirmed."
		} else if missingContext {
			gapNarrative = "Required context is missing to evaluate this rule; treat as incomplete until context is provided."
		} else if len(missing) > 0 {
			gapNarrative = "This attack would require " + strings.Join(missingNames, ", ") + " but no such evidence was observed."
		} else if !precondOK {
			gapNarrative = "Preconditions are not satisfied in the current environment state."
		}
		narrative = append(narrative, narrativeLine(rule, feasible, precondOK, missing))
		rr := ruleResultPool.Get().(*model.RuleResult)
		*rr = model.RuleResult{
			RuleID:             rule.ID,
			Name:               name,
			Feasible:           feasible,
			Conflicted:         contradiction,
			PrecondOK:          precondOK,
			Confidence:         confidence,
			ConfidenceFactors:  &confidenceFactors,
			MissingEvidence:    missing,
			SupportingEvents:   supporting,
			SupportingEventIDs: supportingIDs,
			Explanation:        reason,
			GapNarrative:       gapNarrative,
			ReasonCode:         reasonCodeWithContradiction(precondOK, missing, len(events), contradiction, missingContext, telemetryGap, orderAmbiguous),
			CausalBlockers:     causalBlockers,
			CausalError:        causalErrMsg,
			NecessaryCauses:    necessaryCauses,
			NecessaryCauseSets: necessaryCauseSets,
		}
		results = append(results, *rr)
		*rr = model.RuleResult{}
		ruleResultPool.Put(rr)
	}
	return model.ReasoningReport{
		GeneratedAt:     now,
		Summary:         "Feasibility reasoning over evidence and preconditions.",
		Results:         results,
		Narrative:       narrative,
		ConfidenceModel: "evidence_weighted",
		ConfidenceNote:  "Confidence weighted by evidence coverage, corroboration, and recency. Not ML-calibrated.",
	}
}

func reasonCode(precondOK bool, missing []model.EvidenceRequirement, eventCount int) string {
	switch {
	case !precondOK:
		if hasRequirementGap(missing) {
			return "evidence_gap"
		}
		return "precond_missing"
	case len(missing) > 0 && eventCount == 0:
		return "environment_unknown"
	case len(missing) > 0:
		return "evidence_gap"
	default:
		return "supported"
	}
}

func reasonCodeWithContradiction(precondOK bool, missing []model.EvidenceRequirement, eventCount int, contradiction bool, missingContext bool, telemetryGap bool, orderAmbiguous bool) string {
	if contradiction {
		return "conflicted"
	}
	if missingContext {
		return "environment_unknown"
	}
	if telemetryGap {
		return "telemetry_gap_high_signal"
	}
	if orderAmbiguous {
		return "precond_order_ambiguous"
	}
	return reasonCode(precondOK, missing, eventCount)
}

var telemetryGapSignals = map[string]bool{
	"log_clear":           true,
	"auth_process_modify": true,
}

func hasHighSignalEvidence(index map[string][]int) bool {
	for t := range telemetryGapSignals {
		if len(index[t]) > 0 {
			return true
		}
	}
	return false
}

func hasOrderAmbiguousPreconds(reqs []model.EvidenceRequirement) bool {
	for _, req := range reqs {
		if strings.HasPrefix(req.Type, "precond_order_ambiguous:") {
			return true
		}
	}
	return false
}

func hasRequirementGap(reqs []model.EvidenceRequirement) bool {
	for _, req := range reqs {
		if !strings.HasPrefix(req.Type, "precond:") &&
			!strings.HasPrefix(req.Type, "precond_any:") &&
			!strings.HasPrefix(req.Type, "precond_order:") &&
			!strings.HasPrefix(req.Type, "precond_order_ambiguous:") {
			return true
		}
	}
	return false
}

func hasContradiction(rule Rule, events []model.Event, index map[string][]int) bool {
	types := contradictionsForRule(rule)
	if len(types) == 0 {
		return false
	}
	if contextForRule(rule) == "identity" || contextForRule(rule) == "host" {
		return hasScopedContradiction(rule, events, index, types)
	}
	if hasScopedContradiction(rule, events, index, types) {
		return true
	}
	for _, t := range types {
		if len(index[t]) > 0 {
			return true
		}
	}
	return false
}

func hasContext(events []model.Event, index map[string][]int, kind string) bool {
	if kind == "" {
		return true
	}
	for _, idxs := range index {
		for _, i := range idxs {
			ev := events[i]
			if kind == "host" && ev.Host != "" {
				return true
			}
			if kind == "identity" && ev.User != "" {
				return true
			}
		}
	}
	return false
}

func ApplyConstraints(rep *model.ReasoningReport, constraints []governance.ReasoningConstraint) {
	if len(constraints) == 0 {
		return
	}
	byRule := map[string][]governance.ReasoningConstraint{}
	for _, c := range constraints {
		byRule[c.RuleID] = append(byRule[c.RuleID], c)
	}
	for i := range rep.Results {
		r := &rep.Results[i]
		overridden := false
		for _, c := range byRule[r.RuleID] {
			if c.PolicyImpossible {
				r.PolicyImpossible = true
				r.PolicyReason = c.PolicyReason
				r.Feasible = false
				r.MissingEvidence = nil
				r.ReasonCode = "policy_impossible"
				if c.PolicyReason != "" {
					r.Explanation += " Policy impossible: " + c.PolicyReason
				} else {
					r.Explanation += " Policy impossible by governance constraint."
				}
				overridden = true
			}
			if c.DisableRule {
				r.PolicyImpossible = true
				r.PolicyReason = "disabled_by_tuning"
				r.Feasible = false
				r.MissingEvidence = nil
				r.ReasonCode = "rule_disabled"
				r.Explanation += " Rule disabled by tuning."
				overridden = true
			}
			if c.MinConfidence > 0 && r.Confidence < c.MinConfidence {
				r.PolicyImpossible = true
				r.PolicyReason = fmt.Sprintf("confidence %.2f below tuned minimum %.2f", r.Confidence, c.MinConfidence)
				r.Feasible = false
				r.MissingEvidence = nil
				r.ReasonCode = "min_confidence"
				r.Explanation += " Confidence below tuned minimum."
				overridden = true
			}
			if c.RequireApproval && r.Feasible && !r.PolicyImpossible {
				r.DecisionLabel = "keep"
				r.ReasonCode = "approval_required"
				r.Explanation += " Approval required by tuning."
				overridden = true
			}
			for _, req := range c.RequireEvidence {
				found := false
				for _, ev := range r.SupportingEventIDs {
					if ev == req {
						found = true
						break
					}
				}
				if !found {
					r.MissingEvidence = append(r.MissingEvidence, model.EvidenceRequirement{Type: req, Description: "Required by analyst constraint"})
					r.Feasible = false
					overridden = true
				}
			}
			for _, forbid := range c.ForbidEvidence {
				for _, ev := range r.SupportingEventIDs {
					if ev == forbid {
						r.Feasible = false
						r.Explanation += " Forbidden evidence present by analyst constraint."
						overridden = true
					}
				}
			}
		}
		if overridden {
			if r.ReasonCode == "" {
				r.ReasonCode = "policy_override"
			}
		}
	}
}

func requirementNames(reqs []model.EvidenceRequirement) []string {
	out := make([]string, 0, len(reqs))
	for _, r := range reqs {
		out = append(out, r.Type)
	}
	return out
}

func narrativeLine(rule Rule, feasible bool, precondOK bool, missing []model.EvidenceRequirement) string {
	if feasible {
		return "Proved feasible: " + rule.ID + " (" + rule.Name + ") with all preconditions and evidence satisfied."
	}
	if !precondOK {
		return "Not feasible: " + rule.ID + " (" + rule.Name + ") because preconditions are unmet."
	}
	if len(missing) > 0 {
		return "Incomplete: " + rule.ID + " (" + rule.Name + ") missing evidence " + strings.Join(requirementNames(missing), ", ") + "."
	}
	return "Not feasible: " + rule.ID + " (" + rule.Name + ") due to insufficient evidence."
}

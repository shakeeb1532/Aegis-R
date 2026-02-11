package logic

import (
	"encoding/json"
	"os"
	"strings"
	"time"

	"aegisr/internal/governance"
	"aegisr/internal/model"
	"aegisr/internal/ops"
)

type Rule struct {
	ID           string                      `json:"id"`
	Name         string                      `json:"name"`
	Requirements []model.EvidenceRequirement `json:"requirements"`
	Preconds     []string                    `json:"preconds"`
	Explain      string                      `json:"explain"`
	Mitre        MitreMeta                   `json:"mitre"`
	Provenance   Provenance                  `json:"provenance"`
	Constraints  RuleConstraints             `json:"constraints"`
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

func DefaultRules() []Rule {
	return []Rule{
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
				{Type: "mfa_disabled", Description: "MFA disabled or reset"},
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
				{Type: "valid_account_login", Description: "Login using valid credentials in unusual context"},
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
				{Type: "mfa_disabled", Description: "MFA disabled or bypassed"},
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
			Preconds: []string{"valid_account_login"},
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
			Preconds: []string{"valid_account_login"},
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
				{Type: "valid_account_login", Description: "Login using valid credentials"},
				{Type: "token_reuse", Description: "Token reuse or session replay"},
			},
			Preconds: []string{},
			Explain:  "Stolen credentials used for initial access, often detected by token reuse.",
		},
		{
			ID:   "TA0001.STOLEN_CREDS_ANOMALY",
			Name: "Stolen Credentials with Anomalous Access",
			Requirements: []model.EvidenceRequirement{
				{Type: "valid_account_login", Description: "Login using valid credentials"},
				{Type: "token_reuse", Description: "Token reuse or session replay"},
				{Type: "new_device_login", Description: "New device or unknown client"},
			},
			Preconds: []string{},
			Explain:  "Stolen credentials with anomalous device access indicate initial compromise.",
		},
	}
}

func LoadRules(path string) ([]Rule, error) {
	if path == "" {
		return DefaultRules(), nil
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
	var rules []Rule
	if err := json.Unmarshal(data, &rules); err != nil {
		return nil, err
	}
	if len(rules) == 0 {
		return nil, os.ErrInvalid
	}
	if err := ValidateRules(rules); err != nil {
		return nil, err
	}
	return rules, nil
}

func ValidateRules(rules []Rule) error {
	seen := map[string]bool{}
	for _, r := range rules {
		if r.ID == "" || r.Name == "" {
			return os.ErrInvalid
		}
		if seen[r.ID] {
			return os.ErrInvalid
		}
		seen[r.ID] = true
		if len(r.Requirements) == 0 {
			return os.ErrInvalid
		}
		if r.Constraints.MinConfidence < 0 || r.Constraints.MinConfidence > 1 {
			return os.ErrInvalid
		}
	}
	return nil
}

func Reason(events []model.Event, rules []Rule) model.ReasoningReport {
	return ReasonWithMetrics(events, rules, nil, true)
}

func ReasonWithMetrics(events []model.Event, rules []Rule, metrics *ops.Metrics, includeEvidence bool) model.ReasoningReport {
	index := make(map[string][]model.Event)
	for _, e := range events {
		index[e.Type] = append(index[e.Type], e)
	}
	facts := make(map[string]bool)
	// derive high-level facts from evidence
	facts["initial_access"] = len(index["email_attachment_open"]) > 0 && len(index["macro_execution"]) > 0
	facts["privilege_escalation"] = len(index["token_manipulation"]) > 0 || len(index["admin_group_change"]) > 0
	facts["credential_access"] = len(index["lsass_access"]) > 0 || len(index["process_creation"]) > 0
	facts["c2_established"] = len(index["beacon_outbound"]) > 0 || len(index["dns_tunneling"]) > 0
	facts["identity_compromise"] = len(index["impossible_travel"]) > 0 || len(index["new_device_login"]) > 0 || len(index["mfa_disabled"]) > 0 || len(index["token_refresh_anomaly"]) > 0 || len(index["oauth_consent"]) > 0 || len(index["new_app_grant"]) > 0 || len(index["device_code_flow_success"]) > 0 || len(index["device_join_complete"]) > 0
	facts["valid_account_login"] = len(index["valid_account_login"]) > 0

	results := make([]model.RuleResult, 0, len(rules))
	narrative := []string{}
	for _, rule := range rules {
		if metrics != nil {
			metrics.IncRules(1)
		}
		missing := []model.EvidenceRequirement{}
		supporting := []model.Event{}
		supportingIDs := []string{}
		for _, req := range rule.Requirements {
			if len(index[req.Type]) == 0 {
				missing = append(missing, req)
			} else {
				if includeEvidence {
					supporting = append(supporting, index[req.Type]...)
				}
				for _, ev := range index[req.Type] {
					if ev.ID != "" {
						supportingIDs = append(supportingIDs, ev.ID)
					}
				}
			}
		}
		precondOK := true
		for _, p := range rule.Preconds {
			if !facts[p] {
				precondOK = false
			}
		}
		contradiction := hasContradiction(rule.ID, index)
		contextReq := requiresContext(rule.ID)
		missingContext := false
		if contextReq != "" && !hasContext(index, contextReq) {
			precondOK = false
			missingContext = true
		}
		if contradiction {
			precondOK = false
		}
		feasible := precondOK && len(missing) == 0
		confidence := 0.4
		if feasible {
			confidence = 0.85
		} else if precondOK && len(missing) > 0 {
			confidence = 0.55
		}
		if feasible && rule.Constraints.MinConfidence > 0 && confidence < rule.Constraints.MinConfidence {
			feasible = false
			missing = append(missing, model.EvidenceRequirement{
				Type:        "confidence_threshold",
				Description: "Confidence below rule minimum",
			})
		}
		name := rule.Name
		if !precondOK {
			name = name + " (preconditions unmet)"
		}
		reason := rule.Explain
		missingNames := []string{}
		if contradiction {
			missing = []model.EvidenceRequirement{}
			reason += " Contradictory evidence observed."
		} else if missingContext {
			missing = []model.EvidenceRequirement{
				{Type: "context_missing", Description: "Required context not present for rule evaluation"},
			}
			reason += " Required context missing."
		} else if len(missing) > 0 {
			missingNames = requirementNames(missing)
			reason += " Missing evidence: " + strings.Join(missingNames, ", ")
		}
		gapNarrative := ""
		if contradiction {
			gapNarrative = "Contradictory evidence observed that makes this attack impossible."
		} else if missingContext {
			gapNarrative = "Required context is missing to evaluate this rule; treat as impossible until context is provided."
		} else if len(missing) > 0 {
			gapNarrative = "This attack would require " + strings.Join(missingNames, ", ") + " but no such evidence was observed."
		} else if !precondOK {
			gapNarrative = "Preconditions are not satisfied in the current environment state."
		}
		narrative = append(narrative, narrativeLine(rule, feasible, precondOK, missing))
		results = append(results, model.RuleResult{
			RuleID:             rule.ID,
			Name:               name,
			Feasible:           feasible,
			PrecondOK:          precondOK,
			Confidence:         confidence,
			MissingEvidence:    missing,
			SupportingEvents:   supporting,
			SupportingEventIDs: supportingIDs,
			Explanation:        reason,
			GapNarrative:       gapNarrative,
			ReasonCode:         reasonCodeWithContradiction(precondOK, missing, len(events), contradiction, missingContext),
		})
	}
	return model.ReasoningReport{
		GeneratedAt:     time.Now().UTC(),
		Summary:         "Feasibility reasoning over evidence and preconditions.",
		Results:         results,
		Narrative:       narrative,
		ConfidenceModel: "heuristic",
		ConfidenceNote:  "Rule-based heuristic confidence; not calibrated.",
	}
}

func reasonCode(precondOK bool, missing []model.EvidenceRequirement, eventCount int) string {
	switch {
	case !precondOK:
		return "precond_missing"
	case len(missing) > 0 && eventCount == 0:
		return "insufficient_telemetry"
	case len(missing) > 0:
		return "evidence_gap"
	default:
		return ""
	}
}

func reasonCodeWithContradiction(precondOK bool, missing []model.EvidenceRequirement, eventCount int, contradiction bool, missingContext bool) string {
	if contradiction {
		return "contradiction"
	}
	if missingContext {
		return "context_missing"
	}
	return reasonCode(precondOK, missing, eventCount)
}

func hasContradiction(ruleID string, index map[string][]model.Event) bool {
	contradictions := map[string][]string{
		"TA0006.VALID_ACCOUNTS": {"access_denied"},
		"TA0006.BRUTE_FORCE":    {"mfa_success"},
		"TA0010.BULK_EXFIL":     {"access_denied"},
		"TA0010.EXFIL":          {"access_denied"},
		"TA0008.LATERAL":        {"network_logon_failure"},
		"TA0004.PRIVESCA":       {"privilege_escalation_blocked"},
	}
	types, ok := contradictions[ruleID]
	if !ok {
		return false
	}
	for _, t := range types {
		if len(index[t]) > 0 {
			return true
		}
	}
	return false
}

func requiresContext(ruleID string) string {
	hostRules := map[string]bool{
		"TA0010.EXFIL":                  true,
		"TA0010.BULK_EXFIL":             true,
		"TA0011.C2":                     true,
		"TA0011.APP_LAYER_C2":           true,
		"TA0008.LATERAL":                true,
		"TA0008.ADMIN_PROTOCOL_LATERAL": true,
		"TA0003.PERSIST":                true,
		"TA0003.PERSIST_EXTENDED":       true,
		"TA0040.IMPACT_ENCRYPT":         true,
	}
	identityRules := map[string]bool{
		"TA0006.VALID_ACCOUNTS":   true,
		"TA0006.IDENTITY_ANOMALY": true,
		"TA0004.MFA_BYPASS":       true,
		"TA0004.ACCOUNT_MANIP":    true,
		"TA0003.MAILBOX_PERSIST":  true,
	}
	if hostRules[ruleID] {
		return "host"
	}
	if identityRules[ruleID] {
		return "identity"
	}
	return ""
}

func hasContext(index map[string][]model.Event, kind string) bool {
	if kind == "" {
		return true
	}
	for _, events := range index {
		for _, ev := range events {
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
			r.ReasonCode = "policy_override"
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

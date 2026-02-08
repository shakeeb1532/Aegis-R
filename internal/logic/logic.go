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
	now := time.Now().UTC()
	facts := make(map[string]bool)
	// derive high-level facts from evidence
	facts["initial_access"] = len(index["email_attachment_open"]) > 0 && len(index["macro_execution"]) > 0
	facts["privilege_escalation"] = len(index["token_manipulation"]) > 0 || len(index["admin_group_change"]) > 0
	facts["credential_access"] = len(index["lsass_access"]) > 0 || len(index["process_creation"]) > 0
	facts["c2_established"] = len(index["beacon_outbound"]) > 0 || len(index["dns_tunneling"]) > 0
	facts["identity_compromise"] = len(index["impossible_travel"]) > 0 || len(index["new_device_login"]) > 0 || len(index["mfa_disabled"]) > 0 || len(index["token_refresh_anomaly"]) > 0 || len(index["oauth_consent"]) > 0
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
		presentReqs := 0
		coverageScore := 0.0
		evidenceStrength := 0.0
		recencyAvg := 0.0
		for _, req := range rule.Requirements {
			if len(index[req.Type]) == 0 {
				missing = append(missing, req)
			} else {
				presentReqs++
				strength, recency := requirementStrength(index[req.Type], now)
				evidenceStrength += strength
				recencyAvg += recency
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
		if len(rule.Requirements) > 0 {
			coverageScore = float64(presentReqs) / float64(len(rule.Requirements))
		}
		if presentReqs > 0 {
			evidenceStrength = evidenceStrength / float64(presentReqs)
			recencyAvg = recencyAvg / float64(presentReqs)
		}
		precondOK := true
		for _, p := range rule.Preconds {
			if !facts[p] {
				precondOK = false
			}
		}
		feasible := precondOK && len(missing) == 0
		confidence := confidenceScore(coverageScore, evidenceStrength, precondOK, len(missing) > 0)
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
		if len(missing) > 0 {
			missingNames = requirementNames(missing)
			reason += " Missing evidence: " + strings.Join(missingNames, ", ")
		}
		gapNarrative := ""
		if len(missing) > 0 {
			gapNarrative = "This attack would require " + strings.Join(missingNames, ", ") + " but no such evidence was observed."
		} else if !precondOK {
			gapNarrative = "Preconditions are not satisfied in the current environment state."
		}
		factors := map[string]float64{
			"coverage":          coverageScore,
			"evidence_strength": evidenceStrength,
			"recency":           recencyAvg,
		}
		if precondOK {
			factors["preconditions"] = 1
		} else {
			factors["preconditions"] = 0
		}
		narrative = append(narrative, narrativeLine(rule, feasible, precondOK, missing))
		results = append(results, model.RuleResult{
			RuleID:             rule.ID,
			Name:               name,
			Feasible:           feasible,
			PrecondOK:          precondOK,
			Confidence:         confidence,
			ConfidenceFactors:  factors,
			MissingEvidence:    missing,
			SupportingEvents:   supporting,
			SupportingEventIDs: supportingIDs,
			Explanation:        reason,
			GapNarrative:       gapNarrative,
			ReasonCode:         reasonCode(precondOK, missing, len(events)),
		})
	}
	return model.ReasoningReport{
		GeneratedAt:     time.Now().UTC(),
		Summary:         "Feasibility reasoning over evidence and preconditions.",
		Results:         results,
		Narrative:       narrative,
		ConfidenceModel: "evidence_weighted_v2",
		ConfidenceNote:  "Evidence coverage, recency, and signal strength heuristic; not calibrated.",
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

func requirementStrength(events []model.Event, now time.Time) (float64, float64) {
	if len(events) == 0 {
		return 0, 0
	}
	totalStrength := 0.0
	totalRecency := 0.0
	for _, ev := range events {
		conf := eventConfidence(ev)
		rec := recencyScore(ev, now)
		strength := (conf + rec) / 2
		totalStrength += strength
		totalRecency += rec
	}
	return totalStrength / float64(len(events)), totalRecency / float64(len(events))
}

func eventConfidence(ev model.Event) float64 {
	if ev.Details == nil {
		return 0.6
	}
	if v, ok := ev.Details["confidence"]; ok {
		switch t := v.(type) {
		case float64:
			return clampScore(t)
		case int:
			return clampScore(float64(t))
		}
	}
	return 0.6
}

func recencyScore(ev model.Event, now time.Time) float64 {
	if ev.Time.IsZero() {
		return 0.5
	}
	age := now.Sub(ev.Time)
	switch {
	case age <= time.Hour:
		return 1.0
	case age <= 6*time.Hour:
		return 0.9
	case age <= 24*time.Hour:
		return 0.75
	case age <= 72*time.Hour:
		return 0.55
	case age <= 7*24*time.Hour:
		return 0.35
	default:
		return 0.2
	}
}

func confidenceScore(coverage float64, evidenceStrength float64, precondOK bool, hasMissing bool) float64 {
	precond := 0.0
	if precondOK {
		precond = 1.0
	}
	support := coverage * evidenceStrength
	score := 0.15 + 0.65*support + 0.2*precond
	if hasMissing {
		score -= 0.1
	}
	if !precondOK {
		score -= 0.1
	}
	return clampScore(score)
}

func clampScore(v float64) float64 {
	if v < 0.05 {
		return 0.05
	}
	if v > 0.98 {
		return 0.98
	}
	return v
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

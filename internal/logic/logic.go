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
	facts := make(map[string]bool)
	// derive high-level facts from evidence
	facts["initial_access"] = len(index["email_attachment_open"]) > 0 && len(index["macro_execution"]) > 0
	facts["privilege_escalation"] = len(index["token_manipulation"]) > 0 || len(index["admin_group_change"]) > 0
	facts["credential_access"] = len(index["lsass_access"]) > 0 || len(index["process_creation"]) > 0
	facts["c2_established"] = len(index["beacon_outbound"]) > 0 || len(index["dns_tunneling"]) > 0

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
		narrative = append(narrative, narrativeLine(rule, feasible, precondOK, missing))
		results = append(results, model.RuleResult{
			RuleID:             rule.ID,
			Name:               name,
			Feasible:           feasible,
			Confidence:         confidence,
			MissingEvidence:    missing,
			SupportingEvents:   supporting,
			SupportingEventIDs: supportingIDs,
			Explanation:        reason,
			GapNarrative:       gapNarrative,
		})
	}
	return model.ReasoningReport{
		GeneratedAt: time.Now().UTC(),
		Summary:     "Feasibility reasoning over evidence and preconditions.",
		Results:     results,
		Narrative:   narrative,
	}
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
				}
			}
			for _, forbid := range c.ForbidEvidence {
				for _, ev := range r.SupportingEventIDs {
					if ev == forbid {
						r.Feasible = false
						r.Explanation += " Forbidden evidence present by analyst constraint."
					}
				}
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

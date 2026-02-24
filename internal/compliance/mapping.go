package compliance

import (
	"sort"
	"strings"

	"aman/internal/logic"
)

type RuleControlMapping struct {
	RuleID   string   `json:"rule_id"`
	RuleName string   `json:"rule_name"`
	NistCSF  []string `json:"nist_csf,omitempty"`
	Soc2CC   []string `json:"soc2_cc,omitempty"`
	ISO27001 []string `json:"iso_27001,omitempty"`
}

var nistToSoc2 = map[string][]string{
	"Detect":   {"CC7.2", "CC7.3"},
	"Protect":  {"CC6.1", "CC6.6"},
	"Respond":  {"CC7.4", "CC7.5"},
	"Recover":  {"CC9.2"},
	"Identify": {"CC3.2", "CC3.3"},
	"DE.CM":    {"CC7.2", "CC7.3"},
	"DE.AE":    {"CC7.2", "CC7.4"},
	"PR.AC":    {"CC6.1", "CC6.2"},
	"PR.PT":    {"CC6.6", "CC7.1"},
	"PR.IP":    {"CC8.1"},
	"RS.AN":    {"CC7.4", "CC7.5"},
	"RS.MI":    {"CC7.4", "CC7.5"},
	"ID.RA":    {"CC3.2", "CC3.3"},
	"RC.RP":    {"CC7.5", "CC9.2"},
}

var nistToISO = map[string][]string{
	"Detect":   {"A.8.15", "A.8.16"},
	"Protect":  {"A.8.8", "A.8.9"},
	"Respond":  {"A.5.24", "A.5.26"},
	"Recover":  {"A.5.29", "A.5.30"},
	"Identify": {"A.5.7", "A.5.9"},
	"DE.CM":    {"A.8.16", "A.8.15"},
	"DE.AE":    {"A.5.25", "A.5.26"},
	"PR.AC":    {"A.5.15", "A.8.2"},
	"PR.PT":    {"A.8.8", "A.8.9"},
	"PR.IP":    {"A.8.7"},
	"RS.AN":    {"A.5.24", "A.5.27"},
	"RS.MI":    {"A.5.26", "A.5.30"},
	"ID.RA":    {"A.5.7", "A.5.9"},
	"RC.RP":    {"A.5.29", "A.5.30"},
}

func BuildRuleControlMappings(ruleIDs []string, rules []logic.Rule) []RuleControlMapping {
	if len(ruleIDs) == 0 || len(rules) == 0 {
		return nil
	}
	ruleByID := make(map[string]logic.Rule, len(rules))
	for _, r := range rules {
		ruleByID[r.ID] = r
	}
	out := make([]RuleControlMapping, 0, len(ruleIDs))
	for _, id := range ruleIDs {
		r, ok := ruleByID[id]
		if !ok {
			continue
		}
		nist := dedupeSorted(r.NistCSF)
		soc2 := []string{}
		iso := []string{}
		for _, c := range nist {
			soc2 = append(soc2, nistToSoc2[c]...)
			iso = append(iso, nistToISO[c]...)
		}
		out = append(out, RuleControlMapping{
			RuleID:   r.ID,
			RuleName: r.Name,
			NistCSF:  nist,
			Soc2CC:   dedupeSorted(soc2),
			ISO27001: dedupeSorted(iso),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RuleID < out[j].RuleID })
	return out
}

func ExtractRuleIDsFromFindings(findings []string) []string {
	seen := map[string]bool{}
	ids := []string{}
	for _, f := range findings {
		parts := strings.Fields(f)
		if len(parts) == 0 {
			continue
		}
		id := strings.TrimSpace(parts[0])
		if !strings.HasPrefix(id, "TA") {
			continue
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func dedupeSorted(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

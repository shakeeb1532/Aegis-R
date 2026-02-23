package logic

import "strings"

var attackTacticNameByID = map[string]string{
	"TA0001": "Initial Access",
	"TA0002": "Execution",
	"TA0003": "Persistence",
	"TA0004": "Privilege Escalation",
	"TA0005": "Defense Evasion",
	"TA0006": "Credential Access",
	"TA0007": "Discovery",
	"TA0008": "Lateral Movement",
	"TA0009": "Collection",
	"TA0010": "Exfiltration",
	"TA0011": "Command and Control",
	"TA0040": "Impact",
}

var tacticOverrideByRuleID = map[string]string{
	"TA0006.INSIDER_EXFIL": "TA0010",
	"TA0004.MFA_BYPASS":    "TA0006",
}

func normalizeRuleMetadata(rules []Rule) {
	for i := range rules {
		if rules[i].Mitre.Tactic != "" && rules[i].Mitre.Technique != "" {
			continue
		}
		prefix, suffix := splitRuleID(rules[i].ID)
		if override, ok := tacticOverrideByRuleID[rules[i].ID]; ok {
			prefix = override
		}
		if rules[i].Mitre.Tactic == "" {
			if friendly, ok := attackTacticNameByID[prefix]; ok {
				rules[i].Mitre.Tactic = prefix + " " + friendly
			} else {
				rules[i].Mitre.Tactic = prefix
			}
		}
		if rules[i].Mitre.Technique == "" {
			tech := strings.ReplaceAll(strings.ToLower(suffix), "_", " ")
			if tech == "" {
				tech = strings.ToLower(strings.ReplaceAll(rules[i].Name, " ", "_"))
			}
			rules[i].Mitre.Technique = tech
		}
	}
}

func splitRuleID(id string) (string, string) {
	parts := strings.SplitN(id, ".", 2)
	if len(parts) == 1 {
		return id, ""
	}
	return parts[0], parts[1]
}

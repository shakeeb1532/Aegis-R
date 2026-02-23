package logic

import "sort"

var legacyContradictions = map[string][]string{
	"TA0006.VALID_ACCOUNTS": {"access_denied", "login_denied", "account_locked"},
	"TA0006.BRUTE_FORCE":    {"mfa_success"},
	"TA0010.BULK_EXFIL":     {"access_denied", "egress_blocked"},
	"TA0010.EXFIL":          {"access_denied", "egress_blocked"},
	"TA0008.LATERAL":        {"network_logon_failure", "admin_protocol_denied"},
	"TA0004.PRIVESCA":       {"privilege_escalation_blocked", "admin_action_denied"},
}

var legacyContextByRule = map[string]string{
	"TA0010.EXFIL":                  "host",
	"TA0010.BULK_EXFIL":             "host",
	"TA0011.C2":                     "host",
	"TA0011.APP_LAYER_C2":           "host",
	"TA0008.LATERAL":                "host",
	"TA0008.ADMIN_PROTOCOL_LATERAL": "host",
	"TA0003.PERSIST":                "host",
	"TA0003.PERSIST_EXTENDED":       "host",
	"TA0040.IMPACT_ENCRYPT":         "host",
	"TA0006.VALID_ACCOUNTS":         "identity",
	"TA0006.IDENTITY_ANOMALY":       "identity",
	"TA0004.MFA_BYPASS":             "identity",
	"TA0004.ACCOUNT_MANIP":          "identity",
	"TA0003.MAILBOX_PERSIST":        "identity",
}

var legacyReachabilityByRule = map[string]bool{
	"TA0008.LATERAL":                true,
	"TA0008.ADMIN_PROTOCOL_LATERAL": true,
	"TA0010.EXFIL":                  true,
	"TA0010.EXFIL_WEB":              true,
	"TA0010.BULK_EXFIL":             true,
	"TA0011.C2":                     true,
	"TA0011.APP_LAYER_C2":           true,
	"TA0003.PERSIST":                true,
	"TA0003.PERSIST_EXTENDED":       true,
	"TA0040.IMPACT_ENCRYPT":         true,
}

var legacyHighPrivByRule = map[string]bool{
	"TA0006.CREDDUMP":         true,
	"TA0004.PRIVESCA":         true,
	"TA0005.IMPAIR_DEFENSES":  true,
	"TA0005.AUTH_PROCESS_MOD": true,
	"TA0004.ACCOUNT_MANIP":    true,
	"TA0005.LOG_TAMPER":       true,
}

// NOTE: Keep these legacy maps aligned with Rule fields in logic.go:
// RequiresContext, RequiresReachability, RequiresHighPriv, TargetEventTypes.
// Rule-level values always override these defaults.

var legacyTargetEventTypesByRule = map[string][]string{
	"TA0008.LATERAL":                {"remote_service_creation", "network_logon"},
	"TA0008.ADMIN_PROTOCOL_LATERAL": {"new_inbound_admin_protocol"},
	"TA0010.EXFIL":                  {"large_outbound_transfer", "data_staging"},
	"TA0010.EXFIL_WEB":              {"exfil_web_service"},
	"TA0010.BULK_EXFIL":             {"large_outbound_transfer"},
	"TA0011.C2":                     {"beacon_outbound"},
	"TA0011.APP_LAYER_C2":           {"app_layer_c2", "beacon_outbound"},
	"TA0003.PERSIST":                {"registry_run_key", "scheduled_task"},
	"TA0003.PERSIST_EXTENDED":       {"registry_run_key", "service_install"},
	"TA0040.IMPACT_ENCRYPT":         {"encrypt_activity", "mass_file_rename"},
}

func contradictionsForRule(rule Rule) []string {
	if len(rule.Contradictions) > 0 {
		out := append([]string(nil), rule.Contradictions...)
		sort.Strings(out)
		return out
	}
	out := append([]string(nil), legacyContradictions[rule.ID]...)
	sort.Strings(out)
	return out
}

func contextForRule(rule Rule) string {
	if rule.RequiresContext != "" {
		return rule.RequiresContext
	}
	return legacyContextByRule[rule.ID]
}

func requiresReachability(rule Rule) bool {
	if rule.RequiresReachability != nil {
		return *rule.RequiresReachability
	}
	return legacyReachabilityByRule[rule.ID]
}

func requiresHighPriv(rule Rule) bool {
	if rule.RequiresHighPriv != nil {
		return *rule.RequiresHighPriv
	}
	return legacyHighPrivByRule[rule.ID]
}

func targetEventTypesForRule(rule Rule) []string {
	if len(rule.TargetEventTypes) > 0 {
		return append([]string(nil), rule.TargetEventTypes...)
	}
	return legacyTargetEventTypesByRule[rule.ID]
}

// ContradictionTypes is kept for compatibility with existing scenario generators.
func ContradictionTypes(ruleID string) []string {
	return legacyContradictions[ruleID]
}

func requiresContext(ruleID string) string {
	return legacyContextByRule[ruleID]
}

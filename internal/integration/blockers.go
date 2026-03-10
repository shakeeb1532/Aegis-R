package integration

import "strings"

func blockerTypeFromText(parts ...string) string {
	joined := strings.ToLower(strings.Join(parts, " "))
	joined = strings.TrimSpace(joined)
	if joined == "" {
		return ""
	}
	switch {
	case containsAny(joined, "logging verified intact", "logs verified intact", "trail still logging", "cloudtrail logging remains enabled"):
		return "logging_verified_intact"
	case containsAny(joined, "applocker", "application control", "application whitelist", "application whitelisting") && containsAny(joined, "deny", "denied", "block", "blocked", "prevent", "prevented"):
		return "application_whitelisted"
	case containsAny(joined, "registry") && containsAny(joined, "deny", "denied", "block", "blocked", "prevent", "prevented"):
		return "registry_write_blocked"
	case containsAny(joined, "firewall") && containsAny(joined, "egress", "outbound") && containsAny(joined, "deny", "denied", "block", "blocked", "prevent", "prevented"):
		return "firewall_block_outbound"
	case containsAny(joined, "egress blocked", "outbound blocked", "outbound denied"):
		return "egress_blocked"
	case containsAny(joined, "rdp denied", "winrm denied", "ssh denied", "smb denied", "admin protocol denied"):
		return "admin_protocol_denied"
	case containsAny(joined, "network logon failure", "network login failure"):
		return "network_logon_failure"
	case containsAny(joined, "privilege escalation blocked", "uac blocked", "elevation blocked"):
		return "privilege_escalation_blocked"
	case containsAny(joined, "process blocked", "execution blocked", "execution prevented", "process prevented", "malware prevented"):
		return "process_blocked"
	case containsAny(joined, "admin action denied"):
		return "admin_action_denied"
	case containsAny(joined, "access denied", "accessdenied", "unauthorizedoperation", "permission denied"):
		return "access_denied"
	default:
		return ""
	}
}

func blockerTypeFromCloudTrail(source string, name string, errorCode string, errorMessage string) string {
	joined := strings.ToLower(strings.Join([]string{source, name, errorCode, errorMessage}, " "))
	if !containsAny(joined, "accessdenied", "access denied", "unauthorizedoperation", "permission denied", "operation not permitted") {
		return ""
	}
	nameLower := strings.ToLower(name)
	sourceLower := strings.ToLower(source)
	switch {
	case strings.Contains(sourceLower, "cloudtrail.amazonaws.com") && containsAny(nameLower, "stoplogging", "deletetrail", "updatetrail", "puteventselectors"):
		return "logging_verified_intact"
	case strings.Contains(sourceLower, "ec2.amazonaws.com") && containsAny(nameLower, "authorizesecuritygroupegress", "replacesecuritygroupegress", "createnetworkaclentry"):
		return "firewall_block_outbound"
	case strings.Contains(sourceLower, "ec2.amazonaws.com") && containsAny(nameLower, "authorizesecuritygroupingress", "replacesecuritygroupingress"):
		return "admin_action_denied"
	case containsAny(nameLower, "attachrolepolicy", "attachuserpolicy", "putrolepolicy", "putuserpolicy", "createpolicy", "createuser", "createrole", "addusertogroup"):
		return "admin_action_denied"
	default:
		return "access_denied"
	}
}

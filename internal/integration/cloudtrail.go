package integration

import (
	"encoding/json"
	"strings"

	"aman/internal/model"
)

type cloudTrailEvent struct {
	EventID       string                 `json:"eventID"`
	EventTime     string                 `json:"eventTime"`
	EventSource   string                 `json:"eventSource"`
	EventName     string                 `json:"eventName"`
	AWSRegion     string                 `json:"awsRegion"`
	SourceIP      string                 `json:"sourceIPAddress"`
	UserAgent     string                 `json:"userAgent"`
	RecipientAcct string                 `json:"recipientAccountId"`
	UserIdentity  map[string]interface{} `json:"userIdentity"`
	RequestParams map[string]interface{} `json:"requestParameters"`
	ResponseElems map[string]interface{} `json:"responseElements"`
	Additional    map[string]interface{} `json:"additionalEventData"`
	ErrorCode     string                 `json:"errorCode"`
	ErrorMessage  string                 `json:"errorMessage"`
}

func mapCloudTrail(raw []byte) ([]model.Event, error) {
	var in []cloudTrailEvent
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, err
	}
	out := make([]model.Event, 0, len(in))
	for _, e := range in {
		user := extractUserIdentity(e.UserIdentity)
		details := map[string]interface{}{
			"event_source":  e.EventSource,
			"aws_region":    e.AWSRegion,
			"source_ip":     e.SourceIP,
			"user_agent":    e.UserAgent,
			"error_code":    e.ErrorCode,
			"error_message": e.ErrorMessage,
			"request":       e.RequestParams,
			"response":      e.ResponseElems,
			"additional":    e.Additional,
		}
		for i, etype := range mapCloudTrailEventTypes(e) {
			id := e.EventID
			if i > 0 {
				id = e.EventID + ":" + etype
			}
			out = append(out, model.Event{
				ID:      id,
				Time:    parseTime(e.EventTime),
				Host:    e.RecipientAcct,
				User:    user,
				Type:    etype,
				Details: details,
			})
		}
	}
	return out, nil
}

func extractUserIdentity(m map[string]interface{}) string {
	if m == nil {
		return ""
	}
	if user, ok := m["userName"].(string); ok && user != "" {
		return user
	}
	if arn, ok := m["arn"].(string); ok && arn != "" {
		// Normalize STS session ARNs so thread correlation groups by role.
		parts := strings.Split(arn, "/")
		if len(parts) > 0 {
			return parts[0]
		}
		return arn
	}
	if principal, ok := m["principalId"].(string); ok {
		return principal
	}
	return ""
}

func mapCloudTrailEventTypes(e cloudTrailEvent) []string {
	source := e.EventSource
	name := e.EventName
	errorCode := e.ErrorCode
	errorMessage := e.ErrorMessage
	if blocker := blockerTypeFromCloudTrail(source, name, errorCode, errorMessage); blocker != "" {
		return []string{blocker}
	}
	nameLower := strings.ToLower(name)
	hasError := strings.TrimSpace(errorCode) != "" || strings.TrimSpace(errorMessage) != ""
	if strings.Contains(source, "signin.amazonaws.com") && strings.EqualFold(name, "ConsoleLogin") {
		login := strings.ToLower(asString(responseField(e.ResponseElems, "ConsoleLogin")))
		switch login {
		case "success":
			out := []string{"signin_success"}
			switch strings.ToLower(asString(e.Additional["MFAUsed"])) {
			case "yes":
				out = append(out, "mfa_success")
			case "no":
				out = append(out, "mfa_not_required")
			}
			return out
		case "failure":
			return []string{"access_denied"}
		}
	}
	if strings.Contains(source, "cloudtrail.amazonaws.com") {
		switch {
		case containsAny(nameLower, "stoplogging", "deletetrail"):
			return []string{"disable_logging"}
		case containsAny(nameLower, "updatetrail", "puteventselectors"):
			return []string{"policy_bypass"}
		}
	}
	if strings.Contains(source, "iam.amazonaws.com") || strings.Contains(source, "sts.amazonaws.com") {
		if hasError {
			if blocker := blockerTypeFromText(name, errorCode, errorMessage); blocker != "" {
				return []string{blocker}
			}
			// Failed IAM mutations should not look like successful capability changes.
			return []string{"access_denied"}
		}
		switch {
		case containsAny(nameLower, "createvirtualmfadevice", "enablemfadevice"):
			return []string{"mfa_policy_changed"}
		case containsAny(nameLower, "deactivatemfadevice", "deletevirtualmfadevice", "resyncmfadevice"):
			return []string{"mfa_method_removed"}
		case containsAny(nameLower, "updateassumerolepolicy", "assumerolepolicy", "updatetrustpolicy"):
			return []string{"trust_boundary_change"}
		case containsAny(nameLower, "assumerole"):
			return []string{"role_assume"}
		case containsAny(nameLower, "createuser", "createrole"):
			return []string{"new_admin_account"}
		case containsAny(nameLower, "createpolicy", "createpolicyversion", "deletepolicy", "setdefaultpolicyversion"):
			return []string{"policy_change"}
		case containsAny(nameLower, "addusertogroup", "addroletoinstanceprofile", "attachgrouppolicy"):
			return []string{"admin_group_change"}
		case containsAny(nameLower, "attachrolepolicy", "attachuserpolicy", "putrolepolicy", "putuserpolicy"):
			return []string{"policy_override"}
		default:
			return []string{"iam_change"}
		}
	}
	if strings.Contains(source, "ec2.amazonaws.com") {
		if containsAny(nameLower, "authorizesecuritygroupingress", "authorizesecuritygroupegress") {
			return []string{"new_firewall_rule"}
		}
	}
	return []string{name}
}

func responseField(m map[string]interface{}, key string) interface{} {
	if m == nil {
		return nil
	}
	return m[key]
}

func asString(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

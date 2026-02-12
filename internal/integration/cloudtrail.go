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
		etype := mapCloudTrailEventType(e.EventSource, e.EventName)
		details := map[string]interface{}{
			"event_source":  e.EventSource,
			"aws_region":    e.AWSRegion,
			"source_ip":     e.SourceIP,
			"user_agent":    e.UserAgent,
			"error_code":    e.ErrorCode,
			"error_message": e.ErrorMessage,
			"request":       e.RequestParams,
			"response":      e.ResponseElems,
		}
		out = append(out, model.Event{
			ID:      e.EventID,
			Time:    parseTime(e.EventTime),
			Host:    e.RecipientAcct,
			User:    user,
			Type:    etype,
			Details: details,
		})
	}
	return out, nil
}

func extractUserIdentity(m map[string]interface{}) string {
	if m == nil {
		return ""
	}
	if arn, ok := m["arn"].(string); ok && arn != "" {
		return arn
	}
	if user, ok := m["userName"].(string); ok && user != "" {
		return user
	}
	if principal, ok := m["principalId"].(string); ok {
		return principal
	}
	return ""
}

func mapCloudTrailEventType(source string, name string) string {
	nameLower := strings.ToLower(name)
	if strings.Contains(source, "iam.amazonaws.com") || strings.Contains(source, "sts.amazonaws.com") {
		switch {
		case containsAny(nameLower, "updateassumerolepolicy", "assumerolepolicy", "updatetrustpolicy"):
			return "trust_boundary_change"
		case containsAny(nameLower, "assumerole"):
			return "role_assume"
		case containsAny(nameLower, "createuser", "createrole", "createpolicy"):
			return "new_admin_account"
		case containsAny(nameLower, "addusertogroup", "addroletoinstanceprofile", "attachgrouppolicy"):
			return "admin_group_change"
		case containsAny(nameLower, "attachrolepolicy", "attachuserpolicy", "putrolepolicy", "putuserpolicy"):
			return "policy_override"
		default:
			return "iam_change"
		}
	}
	if strings.Contains(source, "ec2.amazonaws.com") {
		if containsAny(nameLower, "authorizesecuritygroupingress", "authorizesecuritygroupegress") {
			return "new_firewall_rule"
		}
	}
	return name
}

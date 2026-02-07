package integration

import (
	"encoding/json"
	"strings"

	"aegisr/internal/model"
)

type oktaEvent struct {
	EventType string `json:"eventType"`
	Published string `json:"published"`
	Actor     struct {
		ID          string `json:"id"`
		DisplayName string `json:"displayName"`
		AlternateId string `json:"alternateId"`
	} `json:"actor"`
	Client struct {
		IP string `json:"ipAddress"`
		UA string `json:"userAgent"`
	} `json:"client"`
	Target []map[string]interface{} `json:"target"`
}

func mapOktaSystemLog(raw []byte) ([]model.Event, error) {
	var in []oktaEvent
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, err
	}
	out := make([]model.Event, 0, len(in))
	for _, e := range in {
		user := firstNonEmpty(e.Actor.AlternateId, e.Actor.DisplayName, e.Actor.ID)
		etype := mapOktaEventType(e.EventType)
		details := map[string]interface{}{
			"client_ip":  e.Client.IP,
			"user_agent": e.Client.UA,
			"actor_id":   e.Actor.ID,
			"targets":    e.Target,
		}
		out = append(out, model.Event{
			ID:      e.Actor.ID + ":" + e.EventType,
			Time:    parseTime(e.Published),
			Host:    "",
			User:    user,
			Type:    etype,
			Details: details,
		})
	}
	return out, nil
}

func mapOktaEventType(eventType string) string {
	etype := strings.ToLower(eventType)
	switch {
	case strings.Contains(etype, "impossible_travel"):
		return "impossible_travel"
	case strings.Contains(etype, "new_device"):
		return "new_device_login"
	case strings.Contains(etype, "mfa.factor.deactivate") || strings.Contains(etype, "mfa.factor.reset") || strings.Contains(etype, "mfa.factor.suspend"):
		return "mfa_disabled"
	case strings.Contains(etype, "token") && strings.Contains(etype, "refresh"):
		return "token_refresh_anomaly"
	case strings.Contains(etype, "token") && strings.Contains(etype, "revoke"):
		return "token_refresh_anomaly"
	case strings.Contains(etype, "oauth") && strings.Contains(etype, "consent"):
		return "oauth_consent"
	case strings.Contains(etype, "user.session.start") || strings.Contains(etype, "user.authentication") || strings.Contains(etype, "user.session.launch"):
		return "valid_account_login"
	case strings.Contains(etype, "admin") && strings.Contains(etype, "role"):
		return "new_admin_role"
	case strings.HasPrefix(etype, "user.lifecycle"):
		return "iam_change"
	case strings.HasPrefix(etype, "group.user_membership"):
		return "admin_group_change"
	case strings.HasPrefix(etype, "policy.rule"):
		return "policy_override"
	default:
		return eventType
	}
}

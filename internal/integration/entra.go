package integration

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"aman/internal/model"
)

type entraSignIn struct {
	ID                        string `json:"id"`
	CreatedDateTime           string `json:"createdDateTime"`
	UserPrincipalName         string `json:"userPrincipalName"`
	UserDisplayName           string `json:"userDisplayName"`
	UserID                    string `json:"userId"`
	TenantID                  string `json:"tenantId"`
	IPAddress                 string `json:"ipAddress"`
	AppDisplayName            string `json:"appDisplayName"`
	ResourceDisplayName       string `json:"resourceDisplayName"`
	ConditionalAccessStatus   string `json:"conditionalAccessStatus"`
	AuthenticationRequirement string `json:"authenticationRequirement"`
	RiskLevelAggregated       string `json:"riskLevelAggregated"`
	RiskState                 string `json:"riskState"`
	Status                    struct {
		ErrorCode         int    `json:"errorCode"`
		FailureReason     string `json:"failureReason"`
		AdditionalDetails string `json:"additionalDetails"`
	} `json:"status"`
	DeviceDetail struct {
		DeviceID    string `json:"deviceId"`
		DisplayName string `json:"displayName"`
		IsCompliant bool   `json:"isCompliant"`
		IsManaged   bool   `json:"isManaged"`
		TrustType   string `json:"trustType"`
	} `json:"deviceDetail"`
	AuthenticationDetails []struct {
		AuthenticationMethod           string `json:"authenticationMethod"`
		Succeeded                      bool   `json:"succeeded"`
		AuthenticationStepResultDetail string `json:"authenticationStepResultDetail"`
	} `json:"authenticationDetails"`
}

type entraSignInPage struct {
	Value    []entraSignIn `json:"value"`
	NextLink string        `json:"@odata.nextLink"`
}

func ParseEntraSignInPages(raw []byte) ([]entraSignIn, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return nil, errors.New("empty input")
	}
	var pages []json.RawMessage
	switch raw[0] {
	case '[':
		if err := json.Unmarshal(raw, &pages); err != nil {
			return nil, err
		}
	default:
		var wrapper map[string]json.RawMessage
		if err := json.Unmarshal(raw, &wrapper); err != nil {
			return nil, err
		}
		if payload, ok := wrapper["pages"]; ok {
			if err := json.Unmarshal(payload, &pages); err != nil {
				return nil, err
			}
		} else {
			pages = []json.RawMessage{raw}
		}
	}
	out := []entraSignIn{}
	for _, page := range pages {
		var parsed entraSignInPage
		if err := json.Unmarshal(page, &parsed); err != nil {
			return nil, err
		}
		out = append(out, parsed.Value...)
	}
	return out, nil
}

func NormalizeEntraSignIns(raw []byte) ([]model.Event, error) {
	signins, err := ParseEntraSignInPages(raw)
	if err != nil {
		return nil, err
	}
	events := make([]model.Event, 0, len(signins)*2)
	for _, s := range signins {
		events = append(events, normalizeEntraSignIn(s)...)
	}
	return events, nil
}

func normalizeEntraSignIn(s entraSignIn) []model.Event {
	baseDetails := map[string]interface{}{
		"signInId":                s.ID,
		"tenantId":                s.TenantID,
		"userId":                  s.UserID,
		"userPrincipalName":       s.UserPrincipalName,
		"ipAddress":               s.IPAddress,
		"appDisplayName":          s.AppDisplayName,
		"resourceDisplayName":     s.ResourceDisplayName,
		"conditionalAccessStatus": s.ConditionalAccessStatus,
		"statusErrorCode":         s.Status.ErrorCode,
		"statusFailureReason":     s.Status.FailureReason,
		"statusAdditionalDetails": s.Status.AdditionalDetails,
		"riskLevelAggregated":     s.RiskLevelAggregated,
		"riskState":               s.RiskState,
		"deviceId":                s.DeviceDetail.DeviceID,
		"deviceDisplayName":       s.DeviceDetail.DisplayName,
		"deviceIsCompliant":       s.DeviceDetail.IsCompliant,
		"deviceIsManaged":         s.DeviceDetail.IsManaged,
		"deviceTrustType":         s.DeviceDetail.TrustType,
		"source":                  "entra_graph",
	}
	host := firstNonEmpty(s.DeviceDetail.DisplayName, s.DeviceDetail.DeviceID)
	user := firstNonEmpty(s.UserPrincipalName, s.UserDisplayName, s.UserID)
	ts := parseTime(s.CreatedDateTime)

	newEvent := func(typ string) model.Event {
		id := s.ID
		if id != "" {
			id = fmt.Sprintf("%s:%s", id, typ)
		}
		return model.Event{
			ID:      id,
			Time:    ts,
			Host:    host,
			User:    user,
			Type:    typ,
			Details: copyDetails(baseDetails),
		}
	}

	out := []model.Event{newEvent("signin_attempt")}

	if s.Status.ErrorCode == 0 {
		out = append(out, newEvent("signin_success"))
	} else if isPolicyDenied(s) {
		out = append(out, newEvent("signin_denied_policy"))
	} else if isAccountStateDenied(s) {
		out = append(out, newEvent("signin_denied_account_state"))
	} else {
		out = append(out, newEvent("signin_failed_auth"))
	}

	if s.DeviceDetail.DeviceID != "" {
		out = append(out, newEvent("device_registered"))
	}
	if s.DeviceDetail.IsCompliant {
		out = append(out, newEvent("device_compliant"))
	}
	if isNewDeviceLogin(s) {
		out = append(out, newEvent("new_device_login"))
	}

	mfaFailed, sawMfa := authDetailsMFA(s.AuthenticationDetails)
	if mfaFailed {
		out = append(out, newEvent("mfa_challenge_failed"))
	} else if !sawMfa && strings.EqualFold(s.AuthenticationRequirement, "singleFactorAuthentication") {
		out = append(out, newEvent("mfa_not_required"))
	}

	return out
}

func isPolicyDenied(s entraSignIn) bool {
	if s.ConditionalAccessStatus != "" {
		status := strings.ToLower(s.ConditionalAccessStatus)
		if status == "failure" || status == "blocked" {
			return true
		}
	}
	reason := strings.ToLower(s.Status.FailureReason)
	if strings.Contains(reason, "conditional access") {
		return true
	}
	switch s.Status.ErrorCode {
	case 53003, 53004, 53000:
		return true
	default:
		return false
	}
}

func isAccountStateDenied(s entraSignIn) bool {
	reason := strings.ToLower(s.Status.FailureReason)
	if strings.Contains(reason, "disabled") || strings.Contains(reason, "locked") {
		return true
	}
	switch s.Status.ErrorCode {
	case 50057, 50055, 50053, 50144:
		return true
	default:
		return false
	}
}

func isNewDeviceLogin(s entraSignIn) bool {
	if s.DeviceDetail.DeviceID == "" {
		return true
	}
	if !s.DeviceDetail.IsManaged && !s.DeviceDetail.IsCompliant {
		return true
	}
	return false
}

func authDetailsMFA(details []struct {
	AuthenticationMethod           string `json:"authenticationMethod"`
	Succeeded                      bool   `json:"succeeded"`
	AuthenticationStepResultDetail string `json:"authenticationStepResultDetail"`
}) (failed bool, sawMfa bool) {
	for _, d := range details {
		blob := strings.ToLower(d.AuthenticationMethod + " " + d.AuthenticationStepResultDetail)
		if strings.Contains(blob, "mfa") || strings.Contains(blob, "multi") {
			sawMfa = true
			if !d.Succeeded {
				failed = true
			}
		}
	}
	return failed, sawMfa
}

func copyDetails(in map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

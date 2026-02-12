package integration

import (
	"encoding/json"
	"strings"

	"aman/internal/model"
)

type splunkCIMAuth struct {
	Time      string                 `json:"_time"`
	User      string                 `json:"user"`
	SrcUser   string                 `json:"src_user"`
	DestUser  string                 `json:"dest_user"`
	Src       string                 `json:"src"`
	Dest      string                 `json:"dest"`
	Action    string                 `json:"action"`
	App       string                 `json:"app"`
	Signature string                 `json:"signature"`
	Fields    map[string]interface{} `json:"fields"`
}

type splunkCIMNet struct {
	Time      string                 `json:"_time"`
	Src       string                 `json:"src"`
	Dest      string                 `json:"dest"`
	SrcPort   int                    `json:"src_port"`
	DestPort  int                    `json:"dest_port"`
	Transport string                 `json:"transport"`
	Action    string                 `json:"action"`
	BytesIn   int                    `json:"bytes_in"`
	BytesOut  int                    `json:"bytes_out"`
	Fields    map[string]interface{} `json:"fields"`
}

func mapSplunkCIMAuth(raw []byte) ([]model.Event, error) {
	var in []splunkCIMAuth
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, err
	}
	out := make([]model.Event, 0, len(in))
	for _, e := range in {
		user := firstNonEmpty(e.User, e.SrcUser, e.DestUser)
		typeVal := mapSplunkAuthType(e.Action, e.Signature, e.Fields)
		details := map[string]interface{}{
			"src":       e.Src,
			"dest":      e.Dest,
			"app":       e.App,
			"signature": e.Signature,
		}
		merge(details, e.Fields)
		out = append(out, model.Event{
			ID:      e.Src + ":" + e.Dest + ":" + typeVal,
			Time:    parseTime(e.Time),
			Host:    e.Dest,
			User:    user,
			Type:    typeVal,
			Details: details,
		})
	}
	return out, nil
}

func mapSplunkCIMNet(raw []byte) ([]model.Event, error) {
	var in []splunkCIMNet
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, err
	}
	out := make([]model.Event, 0, len(in))
	for _, e := range in {
		etype := mapSplunkNetType(e.Action, e.Transport, e.DestPort, e.BytesOut)
		details := map[string]interface{}{
			"src":       e.Src,
			"dest":      e.Dest,
			"src_port":  e.SrcPort,
			"dest_port": e.DestPort,
			"transport": e.Transport,
			"bytes_in":  e.BytesIn,
			"bytes_out": e.BytesOut,
		}
		merge(details, e.Fields)
		out = append(out, model.Event{
			ID:      e.Src + ":" + e.Dest + ":" + etype,
			Time:    parseTime(e.Time),
			Host:    e.Dest,
			User:    "",
			Type:    etype,
			Details: details,
		})
	}
	return out, nil
}

func mapSplunkAuthType(action string, signature string, fields map[string]interface{}) string {
	joined := strings.ToLower(strings.Join([]string{action, signature, fieldString(fields, "message")}, " "))
	switch {
	case containsAny(joined, "impossible travel", "impossible_travel"):
		return "impossible_travel"
	case containsAny(joined, "new device", "new_device"):
		return "new_device_login"
	case containsAny(joined, "mfa") && containsAny(joined, "disable", "reset", "bypass"):
		return "mfa_disabled"
	case containsAny(joined, "token") && containsAny(joined, "refresh", "replay"):
		return "token_refresh_anomaly"
	case containsAny(joined, "password spray", "password_spray"):
		return "password_spray"
	case containsAny(joined, "credential stuffing", "credential_stuffing"):
		return "credential_stuffing"
	case containsAny(joined, "admin group", "privilege", "role change"):
		return "admin_group_change"
	case containsAny(joined, "oauth", "consent"):
		return "oauth_consent"
	default:
		return firstNonEmpty(action, signature, "authentication")
	}
}

func mapSplunkNetType(action string, transport string, destPort int, bytesOut int) string {
	if bytesOut > 10_000_000 {
		return "large_outbound_transfer"
	}
	if destPort == 3389 || destPort == 445 || destPort == 5985 || destPort == 5986 || destPort == 22 {
		return "new_inbound_admin_protocol"
	}
	return firstNonEmpty(action, transport, "network")
}

func merge(dst map[string]interface{}, src map[string]interface{}) {
	if src == nil {
		return
	}
	for k, v := range src {
		dst[k] = v
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

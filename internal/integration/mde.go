package integration

import (
	"encoding/json"
	"errors"
	"strings"

	"aman/internal/model"
)

type MDEDeviceEvent struct {
	Timestamp   string                 `json:"Timestamp"`
	DeviceName  string                 `json:"DeviceName"`
	AccountName string                 `json:"AccountName"`
	ActionType  string                 `json:"ActionType"`
	Additional  map[string]interface{} `json:"AdditionalFields"`
}

type MDEIdentityEvent struct {
	Timestamp          string                 `json:"Timestamp"`
	DeviceName         string                 `json:"DeviceName"`
	AccountName        string                 `json:"AccountName"`
	TargetAccountUpn   string                 `json:"TargetAccountUpn"`
	AccountDisplayName string                 `json:"AccountDisplayName"`
	ReportId           string                 `json:"ReportId"`
	ActionType         string                 `json:"ActionType"`
	Additional         map[string]interface{} `json:"AdditionalFields"`
}

func mapMDEDevice(raw []byte) ([]model.Event, error) {
	var in []MDEDeviceEvent
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, err
	}
	out := make([]model.Event, 0, len(in))
	for _, e := range in {
		out = append(out, model.Event{
			ID:      e.AccountName + ":" + e.ActionType,
			Time:    parseTime(e.Timestamp),
			Host:    e.DeviceName,
			User:    e.AccountName,
			Type:    mapMDEAction(e.ActionType, e.Additional),
			Details: e.Additional,
		})
	}
	return out, nil
}

func mapMDEIdentity(raw []byte) ([]model.Event, error) {
	var in []MDEIdentityEvent
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, err
	}
	out := make([]model.Event, 0, len(in))
	for _, e := range in {
		user := e.TargetAccountUpn
		if user == "" {
			user = e.AccountDisplayName
		}
		if user == "" {
			user = e.AccountName
		}
		out = append(out, model.Event{
			ID:      e.ReportId,
			Time:    parseTime(e.Timestamp),
			Host:    e.DeviceName,
			User:    user,
			Type:    mapMDEAction(e.ActionType, e.Additional),
			Details: e.Additional,
		})
	}
	return out, nil
}

func mapMDE(raw []byte, kind string) ([]model.Event, error) {
	switch kind {
	case "device":
		return mapMDEDevice(raw)
	case "identity":
		return mapMDEIdentity(raw)
	default:
		return nil, errors.New("unknown mde kind")
	}
}

func mapMDEAction(action string, details map[string]interface{}) string {
	low := strings.ToLower(action)
	cmd := strings.ToLower(fieldStringAny(details, "CommandLine", "InitiatingProcessCommandLine"))
	if containsAny(low, "processcreated", "processcreation") || containsAny(cmd, "cmd.exe", "powershell", "wmic") {
		if containsAny(cmd, "rundll32", "mshta", "certutil", "regsvr32") {
			return "lolbin_execution"
		}
		if containsAny(cmd, "lsass") {
			return "lsass_access"
		}
		return "process_creation"
	}
	if containsAny(low, "lsass") {
		return "lsass_access"
	}
	if containsAny(low, "serviceinstalled", "servicecreated") {
		return "service_install"
	}
	if containsAny(low, "registryvalue", "registrykey") {
		reg := strings.ToLower(fieldStringAny(details, "RegistryKey", "RegistryValue"))
		if containsAny(reg, "\\run", "\\runonce") {
			return "registry_run_key"
		}
		return "registry_change"
	}
	if containsAny(low, "mfa", "auth") && containsAny(low, "disable", "reset", "bypass") {
		return "mfa_disabled"
	}
	if containsAny(low, "token", "oauth") && containsAny(low, "refresh", "grant") {
		return "token_refresh_anomaly"
	}
	if containsAny(low, "addusertogroup", "group") {
		return "admin_group_change"
	}
	if action != "" {
		return action
	}
	return "mde_event"
}

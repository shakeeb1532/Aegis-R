package integration

import (
	"encoding/json"
	"strings"

	"aman/internal/model"
)

type sentinelCSL struct {
	TimeGenerated string                 `json:"TimeGenerated"`
	Computer      string                 `json:"Computer"`
	AccountName   string                 `json:"AccountName"`
	SourceIP      string                 `json:"SourceIP"`
	DestinationIP string                 `json:"DestinationIP"`
	DeviceAction  string                 `json:"DeviceAction"`
	Activity      string                 `json:"Activity"`
	Protocol      string                 `json:"Protocol"`
	Fields        map[string]interface{} `json:"Fields"`
}

func mapSentinelCSL(raw []byte) ([]model.Event, error) {
	var in []sentinelCSL
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, err
	}
	out := make([]model.Event, 0, len(in))
	for _, e := range in {
		etype := classifySentinel(e)
		details := map[string]interface{}{
			"source_ip":      e.SourceIP,
			"destination_ip": e.DestinationIP,
			"protocol":       e.Protocol,
		}
		merge(details, e.Fields)
		out = append(out, model.Event{
			ID:      e.SourceIP + ":" + e.DestinationIP + ":" + etype,
			Time:    parseTime(e.TimeGenerated),
			Host:    e.Computer,
			User:    e.AccountName,
			Type:    etype,
			Details: details,
		})
	}
	return out, nil
}

func classifySentinel(e sentinelCSL) string {
	cmd := strings.ToLower(fieldStringAny(e.Fields, "CommandLine", "ProcessCommandLine"))
	proc := strings.ToLower(fieldStringAny(e.Fields, "ProcessName", "Image", "InitiatingProcessFileName"))
	if proc != "" || cmd != "" {
		if containsAny(cmd, "rundll32", "mshta", "certutil", "regsvr32") || containsAny(proc, "rundll32", "mshta", "certutil", "regsvr32") {
			return "lolbin_execution"
		}
		if containsAny(cmd, "lsass") || containsAny(proc, "lsass") {
			return "lsass_access"
		}
		return "process_creation"
	}
	if hasField(e.Fields, "FileName") || hasField(e.Fields, "FilePath") {
		return "file_change"
	}
	if hasField(e.Fields, "RegistryKey") || hasField(e.Fields, "RegistryValue") {
		reg := strings.ToLower(fieldStringAny(e.Fields, "RegistryKey", "RegistryValue"))
		if containsAny(reg, "\\run", "\\runonce") {
			return "registry_run_key"
		}
		return "registry_change"
	}
	if hasField(e.Fields, "ServiceName") || hasField(e.Fields, "ServiceFileName") {
		return "service_install"
	}
	act := strings.ToLower(firstNonEmpty(e.Activity, e.DeviceAction, ""))
	if act != "" {
		if containsAny(act, "authenticationsuccess", "authentication success", "signin success", "sign-in success", "login success") {
			return "authentication_success"
		}
		if containsAny(act, "authenticationfailure", "authentication failure", "signin failure", "sign-in failure", "login failure") {
			return "authentication_failure"
		}
	}
	return firstNonEmpty(e.Activity, e.DeviceAction, "sentinel_event")
}

func hasField(m map[string]interface{}, key string) bool {
	if m == nil {
		return false
	}
	_, ok := m[key]
	return ok
}

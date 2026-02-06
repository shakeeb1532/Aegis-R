package integration

import (
	"encoding/json"

	"aegisr/internal/model"
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
	if hasField(e.Fields, "ProcessName") || hasField(e.Fields, "CommandLine") {
		return "process_creation"
	}
	if hasField(e.Fields, "FileName") || hasField(e.Fields, "FilePath") {
		return "file_change"
	}
	if hasField(e.Fields, "RegistryKey") || hasField(e.Fields, "RegistryValue") {
		return "registry_change"
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

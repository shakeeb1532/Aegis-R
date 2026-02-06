package integration

import (
	"encoding/json"
	"strconv"
	"time"

	"aegisr/internal/model"
)

type crowdStrikeEvent struct {
	Timestamp       string                 `json:"timestamp"`
	ContextTime     string                 `json:"ContextTimeStamp"`
	EventSimpleName string                 `json:"event_simpleName"`
	AID             string                 `json:"aid"`
	AIP             string                 `json:"aip"`
	ComputerName    string                 `json:"ComputerName"`
	UserName        string                 `json:"UserName"`
	Details         map[string]interface{} `json:"details"`
}

func mapCrowdStrike(raw []byte) ([]model.Event, error) {
	var in []crowdStrikeEvent
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, err
	}
	out := make([]model.Event, 0, len(in))
	for _, e := range in {
		t := parseTime(e.Timestamp)
		if t.IsZero() {
			t = parseUnixMillis(e.ContextTime)
		}
		details := map[string]interface{}{
			"aid": e.AID,
			"aip": e.AIP,
		}
		merge(details, e.Details)
		out = append(out, model.Event{
			ID:      e.AID + ":" + e.EventSimpleName,
			Time:    t,
			Host:    e.ComputerName,
			User:    e.UserName,
			Type:    mapCrowdStrikeType(e.EventSimpleName),
			Details: details,
		})
	}
	return out, nil
}

func parseUnixMillis(v string) time.Time {
	if v == "" {
		return time.Time{}
	}
	ms, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return time.Time{}
	}
	return time.Unix(0, ms*int64(time.Millisecond))
}

func mapCrowdStrikeType(name string) string {
	switch name {
	case "ProcessRollup2", "ProcessRollup":
		return "process_creation"
	case "FileCreateInfo":
		return "file_create"
	case "FileWriteInfo":
		return "file_modify"
	case "FileDeleteInfo":
		return "file_delete"
	case "RegistryValueSet", "RegistryKeyCreated":
		return "registry_change"
	default:
		return name
	}
}

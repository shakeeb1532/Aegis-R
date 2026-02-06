package integration

import (
	"encoding/json"
	"errors"

	"aegisr/internal/model"
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
			Type:    e.ActionType,
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
			Type:    "identity_event",
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

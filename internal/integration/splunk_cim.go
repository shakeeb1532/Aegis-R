package integration

import (
	"encoding/json"

	"aegisr/internal/model"
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
		typeVal := firstNonEmpty(e.Action, e.Signature, "authentication")
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
		etype := firstNonEmpty(e.Action, e.Transport, "network")
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

package integration

import (
	"encoding/json"
	"errors"

	"aegisr/internal/model"
)

type Schema string

const (
	SchemaNative      Schema = "native"
	SchemaECS         Schema = "ecs"
	SchemaOCSF        Schema = "ocsf"
	SchemaCIM         Schema = "cim"
	SchemaMDE         Schema = "mde"
	SchemaElasticECS  Schema = "elastic_ecs"
	SchemaSplunkAuth  Schema = "splunk_cim_auth"
	SchemaSplunkNet   Schema = "splunk_cim_net"
	SchemaOkta        Schema = "okta_systemlog"
	SchemaCloudTrail  Schema = "aws_cloudtrail"
	SchemaSentinelCSL Schema = "sentinel_csl"
	SchemaCrowdStrike Schema = "crowdstrike_fdr"
	SchemaWindowsLog  Schema = "windows_eventlog"
)

type IngestOptions struct {
	Schema Schema `json:"schema"`
	Kind   string `json:"kind"`
}

// IngestEvents maps supported schemas to the internal event model.
func IngestEvents(raw []byte, opts IngestOptions) ([]model.Event, error) {
	if opts.Schema == "" || opts.Schema == Schema("auto") {
		opts.Schema = detectSchema(raw, opts.Kind)
	}
	switch opts.Schema {
	case SchemaNative:
		var events []model.Event
		if err := json.Unmarshal(raw, &events); err != nil {
			return nil, err
		}
		return events, nil
	case SchemaECS:
		return mapECS(raw)
	case SchemaElasticECS:
		return mapElasticECS(raw)
	case SchemaOCSF:
		return mapOCSF(raw)
	case SchemaCIM:
		return mapCIM(raw)
	case SchemaSplunkAuth:
		return mapSplunkCIMAuth(raw)
	case SchemaSplunkNet:
		return mapSplunkCIMNet(raw)
	case SchemaMDE:
		return mapMDE(raw, opts.Kind)
	case SchemaOkta:
		return mapOktaSystemLog(raw)
	case SchemaCloudTrail:
		return mapCloudTrail(raw)
	case SchemaSentinelCSL:
		return mapSentinelCSL(raw)
	case SchemaCrowdStrike:
		return mapCrowdStrike(raw)
	case SchemaWindowsLog:
		return mapWindowsEventLog(raw)
	default:
		return nil, errors.New("unsupported schema")
	}
}

func detectSchema(raw []byte, kind string) Schema {
	// Try to decode a single object or array for shape inspection.
	var single map[string]interface{}
	if err := json.Unmarshal(raw, &single); err == nil && len(single) > 0 {
		if looksLikeCloudTrail(single) {
			return SchemaCloudTrail
		}
		if looksLikeWindowsEvent(single) {
			return SchemaWindowsLog
		}
		if looksLikeOkta(single) {
			return SchemaOkta
		}
	}
	var list []map[string]interface{}
	if err := json.Unmarshal(raw, &list); err == nil && len(list) > 0 {
		if looksLikeCloudTrail(list[0]) {
			return SchemaCloudTrail
		}
		if looksLikeWindowsEvent(list[0]) {
			return SchemaWindowsLog
		}
		if looksLikeOkta(list[0]) {
			return SchemaOkta
		}
		if looksLikeECS(list[0]) {
			return SchemaECS
		}
		if looksLikeOCSF(list[0]) {
			return SchemaOCSF
		}
		if looksLikeCIM(list[0]) {
			return SchemaCIM
		}
		if looksLikeElasticECS(list[0]) {
			return SchemaElasticECS
		}
		if looksLikeSplunkCIMAuth(list[0]) {
			return SchemaSplunkAuth
		}
		if looksLikeSplunkCIMNet(list[0]) {
			return SchemaSplunkNet
		}
		if looksLikeSentinel(list[0]) {
			return SchemaSentinelCSL
		}
		if looksLikeCrowdStrike(list[0]) {
			return SchemaCrowdStrike
		}
	}
	if kind != "" {
		return SchemaMDE
	}
	return SchemaNative
}

func looksLikeCloudTrail(m map[string]interface{}) bool {
	_, ok1 := m["eventID"]
	_, ok2 := m["eventSource"]
	_, ok3 := m["eventName"]
	return ok1 && ok2 && ok3
}

func looksLikeWindowsEvent(m map[string]interface{}) bool {
	_, ok1 := m["EventID"]
	_, ok2 := m["Hostname"]
	return ok1 && ok2
}

func looksLikeOkta(m map[string]interface{}) bool {
	_, ok1 := m["eventType"]
	_, ok2 := m["actor"]
	return ok1 && ok2
}

func looksLikeECS(m map[string]interface{}) bool {
	_, ok1 := m["event"]
	_, ok2 := m["@timestamp"]
	return ok1 && ok2
}

func looksLikeElasticECS(m map[string]interface{}) bool {
	_, ok1 := m["event"]
	_, ok2 := m["agent"]
	return ok1 && ok2
}

func looksLikeOCSF(m map[string]interface{}) bool {
	_, ok1 := m["type_name"]
	_, ok2 := m["event_uid"]
	return ok1 && ok2
}

func looksLikeCIM(m map[string]interface{}) bool {
	_, ok1 := m["action"]
	_, ok2 := m["host"]
	return ok1 && ok2
}

func looksLikeSplunkCIMAuth(m map[string]interface{}) bool {
	if v, ok := m["action"].(string); ok && v != "" {
		_, ok2 := m["user"]
		return ok2
	}
	return false
}

func looksLikeSplunkCIMNet(m map[string]interface{}) bool {
	if v, ok := m["dest"].(string); ok && v != "" {
		_, ok2 := m["src"]
		return ok2
	}
	return false
}

func looksLikeSentinel(m map[string]interface{}) bool {
	_, ok1 := m["TimeGenerated"]
	_, ok2 := m["Computer"]
	return ok1 && ok2
}

func looksLikeCrowdStrike(m map[string]interface{}) bool {
	_, ok1 := m["event_simpleName"]
	_, ok2 := m["timestamp"]
	return ok1 && ok2
}

type ecsEvent struct {
	Event struct {
		ID   string   `json:"id"`
		Kind string   `json:"kind"`
		Type []string `json:"type"`
	} `json:"event"`
	Host struct {
		Name string `json:"name"`
	} `json:"host"`
	User struct {
		Name string `json:"name"`
	} `json:"user"`
	Timestamp string                 `json:"@timestamp"`
	Labels    map[string]interface{} `json:"labels"`
}

func mapECS(raw []byte) ([]model.Event, error) {
	var in []ecsEvent
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, err
	}
	out := make([]model.Event, 0, len(in))
	for _, e := range in {
		etype := "ecs_event"
		if len(e.Event.Type) > 0 {
			etype = e.Event.Type[0]
		}
		out = append(out, model.Event{
			ID:      e.Event.ID,
			Time:    parseTime(e.Timestamp),
			Host:    e.Host.Name,
			User:    e.User.Name,
			Type:    etype,
			Details: e.Labels,
		})
	}
	return out, nil
}

type ocsfEvent struct {
	EventUID   string                 `json:"event_uid"`
	TypeName   string                 `json:"type_name"`
	Time       string                 `json:"time"`
	Hostname   string                 `json:"hostname"`
	Username   string                 `json:"user_name"`
	Attributes map[string]interface{} `json:"attributes"`
}

func mapOCSF(raw []byte) ([]model.Event, error) {
	var in []ocsfEvent
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, err
	}
	out := make([]model.Event, 0, len(in))
	for _, e := range in {
		out = append(out, model.Event{
			ID:      e.EventUID,
			Time:    parseTime(e.Time),
			Host:    e.Hostname,
			User:    e.Username,
			Type:    e.TypeName,
			Details: e.Attributes,
		})
	}
	return out, nil
}

type cimEvent struct {
	ID     string                 `json:"_time"`
	Source string                 `json:"source"`
	User   string                 `json:"user"`
	Host   string                 `json:"host"`
	Action string                 `json:"action"`
	Fields map[string]interface{} `json:"fields"`
}

func mapCIM(raw []byte) ([]model.Event, error) {
	var in []cimEvent
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, err
	}
	out := make([]model.Event, 0, len(in))
	for _, e := range in {
		out = append(out, model.Event{
			ID:      e.ID,
			Time:    parseTime(e.ID),
			Host:    e.Host,
			User:    e.User,
			Type:    e.Action,
			Details: e.Fields,
		})
	}
	return out, nil
}

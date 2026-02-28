package integration

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"aman/internal/model"
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
	SchemaEntraGraph  Schema = "entra_signins_graph"
)

type IngestOptions struct {
	Schema Schema `json:"schema"`
	Kind   string `json:"kind"`
}

// IngestEvents maps supported schemas to the internal event model.
func IngestEvents(raw []byte, opts IngestOptions) ([]model.Event, error) {
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
	case SchemaEntraGraph:
		return NormalizeEntraSignIns(raw)
	default:
		return nil, errors.New("unsupported schema")
	}
}

type ecsEvent struct {
	Event struct {
		ID       string   `json:"id"`
		Kind     string   `json:"kind"`
		Action   string   `json:"action"`
		Category []string `json:"category"`
		Type     []string `json:"type"`
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
		etype := normalizeInternalEventType(firstNonEmpty(
			e.Event.Action,
			firstSlice(e.Event.Type),
			firstSlice(e.Event.Category),
			e.Event.Kind,
			"ecs_event",
		))
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
	Time   string                 `json:"_time"`
	ID     string                 `json:"event_id"`
	CD     string                 `json:"_cd"`
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
		id := firstNonEmpty(e.ID, e.CD)
		if id == "" {
			id = hashEventID(e.Time, e.Source, e.Host, e.User, e.Action)
		}
		out = append(out, model.Event{
			ID:      id,
			Time:    parseTime(e.Time),
			Host:    e.Host,
			User:    e.User,
			Type:    normalizeInternalEventType(e.Action),
			Details: e.Fields,
		})
	}
	return out, nil
}

func normalizeInternalEventType(v string) string {
	s := strings.ToLower(strings.TrimSpace(v))
	switch s {
	case "", "ecs_event", "event":
		return "event"
	case "process", "process_start", "start":
		return "process_creation"
	case "authentication", "auth", "login", "user_login":
		return "signin_success"
	case "auth_failed", "login_failed", "authentication_failure":
		return "signin_failed_auth"
	case "auth_denied_policy", "login_denied_policy":
		return "signin_denied_policy"
	case "account_locked", "account_disabled":
		return "signin_denied_account_state"
	case "network", "connection", "network_connection":
		return "network_connection"
	case "privilege_change", "role_change":
		return "admin_group_change"
	default:
		return s
	}
}

func hashEventID(parts ...string) string {
	h := sha1.New() //nolint:gosec // non-crypto identifier only
	_, _ = h.Write([]byte(strings.Join(parts, "|")))
	return fmt.Sprintf("evt-%s", hex.EncodeToString(h.Sum(nil)))
}

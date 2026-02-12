package integration

import (
	"encoding/json"
	"strings"

	"aman/internal/model"
)

type elasticECSEvent struct {
	Timestamp string `json:"@timestamp"`
	Event     struct {
		ID       string   `json:"id"`
		Action   string   `json:"action"`
		Category []string `json:"category"`
		Type     []string `json:"type"`
		Kind     string   `json:"kind"`
	} `json:"event"`
	Source struct {
		IP string `json:"ip"`
	} `json:"source"`
	Destination struct {
		IP   string `json:"ip"`
		Port int    `json:"port"`
	} `json:"destination"`
	Network struct {
		Transport string `json:"transport"`
	} `json:"network"`
	Host struct {
		Name string `json:"name"`
	} `json:"host"`
	User struct {
		Name string `json:"name"`
	} `json:"user"`
	Message string                 `json:"message"`
	Labels  map[string]interface{} `json:"labels"`
}

func mapElasticECS(raw []byte) ([]model.Event, error) {
	var in []elasticECSEvent
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, err
	}
	out := make([]model.Event, 0, len(in))
	for _, e := range in {
		typeVal := classifyECS(e)
		details := map[string]interface{}{
			"message":     e.Message,
			"kind":        e.Event.Kind,
			"source_ip":   e.Source.IP,
			"dest_ip":     e.Destination.IP,
			"dest_port":   e.Destination.Port,
			"transport":   e.Network.Transport,
			"event_kind":  e.Event.Kind,
			"event_type":  e.Event.Type,
			"event_class": e.Event.Category,
		}
		merge(details, e.Labels)
		out = append(out, model.Event{
			ID:      e.Event.ID,
			Time:    parseTime(e.Timestamp),
			Host:    e.Host.Name,
			User:    e.User.Name,
			Type:    typeVal,
			Details: details,
		})
	}
	return out, nil
}

func firstSlice(v []string) string {
	if len(v) == 0 {
		return ""
	}
	return v[0]
}

func classifyECS(e elasticECSEvent) string {
	categories := e.Event.Category
	types := e.Event.Type
	action := strings.ToLower(e.Event.Action)
	message := strings.ToLower(e.Message)
	if contains(categories, "process") && contains(types, "start") {
		if containsAny(message, "lsass") {
			return "lsass_access"
		}
		return "process_creation"
	}
	if contains(categories, "file") {
		if contains(types, "creation") {
			return "file_create"
		}
		if contains(types, "deletion") {
			return "file_delete"
		}
		if contains(types, "change") || contains(types, "modify") {
			return "file_modify"
		}
	}
	if contains(categories, "registry") {
		if containsAny(action, "run", "runkey") {
			return "registry_run_key"
		}
		if contains(types, "change") || contains(types, "creation") {
			return "registry_change"
		}
	}
	if contains(categories, "iam") {
		switch {
		case containsAny(action, "add_member", "add_to_group", "group") || containsAny(action, "admin", "role"):
			return "admin_group_change"
		case containsAny(action, "policy", "trust"):
			return "policy_override"
		default:
			return "iam_change"
		}
	}
	if contains(categories, "authentication") {
		switch {
		case containsAny(action, "impossible_travel"):
			return "impossible_travel"
		case containsAny(action, "new_device"):
			return "new_device_login"
		case containsAny(action, "mfa") && containsAny(action, "disable", "reset", "bypass"):
			return "mfa_disabled"
		case containsAny(action, "token") && containsAny(action, "refresh", "replay"):
			return "token_refresh_anomaly"
		case containsAny(action, "password_spray", "bruteforce"):
			return "password_spray"
		default:
			return "valid_account_login"
		}
	}
	if contains(categories, "network") && e.Destination.Port != 0 {
		if e.Destination.Port == 3389 || e.Destination.Port == 445 || e.Destination.Port == 5985 || e.Destination.Port == 5986 || e.Destination.Port == 22 {
			return "new_inbound_admin_protocol"
		}
	}
	return firstNonEmpty(action, firstSlice(types), firstSlice(categories), "ecs_event")
}

func contains(list []string, v string) bool {
	for _, item := range list {
		if item == v {
			return true
		}
	}
	return false
}

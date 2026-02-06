package integration

import (
	"encoding/json"

	"aegisr/internal/model"
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
		typeVal := classifyECS(e.Event.Category, e.Event.Type, e.Event.Action)
		details := map[string]interface{}{"message": e.Message, "kind": e.Event.Kind}
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

func classifyECS(categories []string, types []string, action string) string {
	if contains(categories, "process") && contains(types, "start") {
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
		if contains(types, "change") || contains(types, "creation") {
			return "registry_change"
		}
	}
	if contains(categories, "iam") {
		return "iam_change"
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

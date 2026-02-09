package integration

import (
	"encoding/json"
	"fmt"
	"strings"

	"aegisr/internal/model"
)

type windowsEvent struct {
	EventID         int    `json:"EventID"`
	Channel         string `json:"Channel"`
	Hostname        string `json:"Hostname"`
	SubjectUserName string `json:"SubjectUserName"`
	User            string `json:"User"`
	NewProcessName  string `json:"NewProcessName"`
	CommandLine     string `json:"CommandLine"`
	ParentProcess   string `json:"ParentProcessName"`
	Message         string `json:"Message"`
	TimeCreated     string `json:"TimeCreated"`
	Timestamp       string `json:"@timestamp"`
}

func mapWindowsEventLog(raw []byte) ([]model.Event, error) {
	lines := splitLines(raw)
	out := []model.Event{}
	for _, line := range lines {
		var ev windowsEvent
		if err := json.Unmarshal(line, &ev); err != nil {
			continue
		}
		ts := firstNonEmptyWin(ev.Timestamp, ev.TimeCreated)
		time := parseTime(ts)
		baseID := fmt.Sprintf("%s-%d-%s", ts, ev.EventID, ev.Hostname)
		user := firstNonEmptyWin(ev.SubjectUserName, ev.User)
		host := ev.Hostname
		details := map[string]interface{}{
			"channel": ev.Channel,
			"message": ev.Message,
		}

		switch ev.EventID {
		case 1102:
			out = append(out, model.Event{
				ID:      baseID + "-logclear",
				Time:    time,
				Host:    host,
				User:    user,
				Type:    "disable_logging",
				Details: details,
			})
		case 4688, 1:
			out = append(out, model.Event{
				ID:      baseID + "-proc",
				Time:    time,
				Host:    host,
				User:    user,
				Type:    "process_creation",
				Details: map[string]interface{}{
					"image":        ev.NewProcessName,
					"command_line": ev.CommandLine,
					"parent":       ev.ParentProcess,
				},
			})
			if isLolbin(ev.NewProcessName, ev.CommandLine) {
				out = append(out, model.Event{
					ID:      baseID + "-lolbin",
					Time:    time,
					Host:    host,
					User:    user,
					Type:    "lolbin_execution",
					Details: map[string]interface{}{
						"image":        ev.NewProcessName,
						"command_line": ev.CommandLine,
					},
				})
			}
		case 4625:
			out = append(out, model.Event{
				ID:      baseID + "-fail",
				Time:    time,
				Host:    host,
				User:    user,
				Type:    "password_spray",
				Details: details,
			})
		case 4624:
			out = append(out, model.Event{
				ID:      baseID + "-login",
				Time:    time,
				Host:    host,
				User:    user,
				Type:    "valid_account_login",
				Details: details,
			})
		case 4697, 7045:
			out = append(out, model.Event{
				ID:      baseID + "-service",
				Time:    time,
				Host:    host,
				User:    user,
				Type:    "service_install",
				Details: details,
			})
		case 4698:
			out = append(out, model.Event{
				ID:      baseID + "-task",
				Time:    time,
				Host:    host,
				User:    user,
				Type:    "scheduled_task",
				Details: details,
			})
		case 4657:
			out = append(out, model.Event{
				ID:      baseID + "-registry",
				Time:    time,
				Host:    host,
				User:    user,
				Type:    "registry_run_key",
				Details: details,
			})
		}
	}
	return out, nil
}

func splitLines(raw []byte) [][]byte {
	lines := [][]byte{}
	start := 0
	for i := 0; i < len(raw); i++ {
		if raw[i] == '\n' {
			if i > start {
				lines = append(lines, raw[start:i])
			}
			start = i + 1
		}
	}
	if start < len(raw) {
		lines = append(lines, raw[start:])
	}
	return lines
}

func firstNonEmptyWin(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func isLolbin(image string, cmd string) bool {
	s := strings.ToLower(image + " " + cmd)
	return strings.Contains(s, "mshta") ||
		strings.Contains(s, "rundll32") ||
		strings.Contains(s, "certutil") ||
		strings.Contains(s, "regsvr32") ||
		strings.Contains(s, "wmic")
}

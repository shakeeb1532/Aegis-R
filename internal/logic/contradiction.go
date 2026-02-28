package logic

import (
	"fmt"

	"aman/internal/model"
)

func hasScopedContradiction(rule Rule, events []model.Event, index map[string][]int, contradictionTypes []string) bool {
	reqScopes := map[string]bool{}
	for _, req := range rule.Requirements {
		for _, idx := range index[req.Type] {
			if idx < 0 || idx >= len(events) {
				continue
			}
			scope := eventScopeKey(events[idx])
			if scope != "" {
				reqScopes[scope] = true
			}
		}
	}
	if len(reqScopes) == 0 {
		return false
	}
	for _, t := range contradictionTypes {
		for _, idx := range index[t] {
			if idx < 0 || idx >= len(events) {
				continue
			}
			scope := eventScopeKey(events[idx])
			if scope == "" {
				continue
			}
			if reqScopes[scope] {
				return true
			}
		}
	}
	return false
}

func eventScopeKey(ev model.Event) string {
	if ev.Details == nil {
		return ""
	}
	if v := detailString(ev.Details, "signInId"); v != "" {
		return "signInId:" + v
	}
	if v := detailString(ev.Details, "sessionId"); v != "" {
		return "sessionId:" + v
	}
	if v := detailString(ev.Details, "correlationId"); v != "" {
		return "correlationId:" + v
	}
	return ""
}

func detailString(details map[string]interface{}, key string) string {
	raw, ok := details[key]
	if !ok || raw == nil {
		return ""
	}
	switch v := raw.(type) {
	case string:
		return v
	default:
		return fmt.Sprint(v)
	}
}

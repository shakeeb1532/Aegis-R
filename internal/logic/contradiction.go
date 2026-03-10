package logic

import (
	"fmt"
	"sort"

	"aman/internal/model"
)

func hasScopedContradiction(rule Rule, events []model.Event, index map[string][]int, contradictionTypes []string) bool {
	reqScopes := map[string]bool{}
	for _, req := range rule.Requirements {
		for _, idx := range index[req.Type] {
			if idx < 0 || idx >= len(events) {
				continue
			}
			for _, scope := range eventScopeKeys(events[idx]) {
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
			for _, scope := range eventScopeKeys(events[idx]) {
				if reqScopes[scope] {
					return true
				}
			}
		}
	}
	return false
}

func eventScopeKeys(ev model.Event) []string {
	set := map[string]bool{}
	add := func(v string) {
		if v != "" {
			set[v] = true
		}
	}
	if ev.Details != nil {
		if v := detailString(ev.Details, "signInId"); v != "" {
			add("signInId:" + v)
		}
		if v := detailString(ev.Details, "sessionId"); v != "" {
			add("sessionId:" + v)
		}
		if v := detailString(ev.Details, "correlationId"); v != "" {
			add("correlationId:" + v)
		}
		if v := detailString(ev.Details, "processGuid"); v != "" {
			add("processGuid:" + v)
		}
		if v := detailString(ev.Details, "parentProcessGuid"); v != "" {
			add("parentProcessGuid:" + v)
		}
	}
	if ev.Host != "" && ev.User != "" {
		add("hostUser:" + ev.Host + "|" + ev.User)
	}
	if ev.Host != "" {
		add("host:" + ev.Host)
	}
	if ev.User != "" {
		add("user:" + ev.User)
	}
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
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

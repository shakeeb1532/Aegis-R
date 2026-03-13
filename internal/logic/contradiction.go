package logic

import (
	"fmt"
	"sort"
	"strings"

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
			if scopeMatch(reqScopes, eventScopeKeys(events[idx])) {
				return true
			}
		}
	}
	return false
}

func scopeMatch(required map[string]bool, candidate []string) bool {
	reqStrong, reqMedium, reqBroad := splitScopes(mapKeys(required))
	candStrong, candMedium, candBroad := splitScopes(candidate)

	if len(reqStrong) > 0 && len(candStrong) > 0 {
		return intersects(reqStrong, candStrong)
	}
	if len(reqMedium) > 0 && len(candMedium) > 0 {
		return intersectionCount(reqMedium, candMedium) >= 2
	}
	if len(reqBroad) > 0 && len(candBroad) > 0 {
		return intersects(reqBroad, candBroad)
	}
	return false
}

func splitScopes(scopes []string) (strong []string, medium []string, broad []string) {
	for _, scope := range scopes {
		switch {
		case hasScopePrefix(scope, "signInId:", "sessionId:", "correlationId:", "processGuid:", "parentProcessGuid:", "logonId:"):
			strong = append(strong, scope)
		case hasScopePrefix(scope, "sourceIP:", "sourceHost:", "logonType:"):
			medium = append(medium, scope)
		case hasScopePrefix(scope, "hostUser:", "host:", "user:"):
			broad = append(broad, scope)
		}
	}
	return strong, medium, broad
}

func hasScopePrefix(scope string, prefixes ...string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(scope, prefix) {
			return true
		}
	}
	return false
}

func intersects(a []string, b []string) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	seen := make(map[string]bool, len(a))
	for _, item := range a {
		seen[item] = true
	}
	for _, item := range b {
		if seen[item] {
			return true
		}
	}
	return false
}

func intersectionCount(a []string, b []string) int {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	seen := make(map[string]bool, len(a))
	for _, item := range a {
		seen[item] = true
	}
	count := 0
	for _, item := range b {
		if seen[item] {
			count++
		}
	}
	return count
}

func mapKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func eventScopeKeys(ev model.Event) []string {
	set := map[string]bool{}
	add := func(v string) {
		if v != "" {
			set[v] = true
		}
	}
	if ev.Details != nil {
		if v := firstDetailString(ev.Details, "signInId", "sign_in_id"); v != "" {
			add("signInId:" + v)
		}
		if v := firstDetailString(ev.Details, "sessionId", "session_id"); v != "" {
			add("sessionId:" + v)
		}
		if v := firstDetailString(ev.Details, "correlationId", "correlation_id"); v != "" {
			add("correlationId:" + v)
		}
		if v := firstDetailString(ev.Details, "processGuid", "process_guid"); v != "" {
			add("processGuid:" + v)
		}
		if v := firstDetailString(ev.Details, "parentProcessGuid", "parent_process_guid"); v != "" {
			add("parentProcessGuid:" + v)
		}
		if v := firstDetailString(ev.Details, "logonId", "logon_id", "TargetLogonId", "SubjectLogonId"); v != "" {
			add("logonId:" + v)
		}
		if v := firstDetailString(ev.Details, "source_ip", "IpAddress", "SourceNetworkAddress", "ClientAddress"); v != "" {
			add("sourceIP:" + v)
		}
		if v := firstDetailString(ev.Details, "source_host", "WorkstationName", "IpHostname", "SourceWorkstation"); v != "" {
			add("sourceHost:" + v)
		}
		if v := firstDetailString(ev.Details, "logon_type", "LogonType", "LogonTypeName"); v != "" {
			add("logonType:" + v)
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

func firstDetailString(details map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if v := detailString(details, key); v != "" {
			return v
		}
	}
	return ""
}

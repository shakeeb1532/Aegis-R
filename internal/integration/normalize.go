package integration

import (
	"fmt"
	"strings"
)

func lower(v string) string {
	return strings.ToLower(v)
}

func containsAny(v string, needles ...string) bool {
	for _, n := range needles {
		if n == "" {
			continue
		}
		if strings.Contains(v, n) {
			return true
		}
	}
	return false
}

func fieldString(m map[string]interface{}, key string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[key]; ok {
		switch t := v.(type) {
		case nil:
			return ""
		case string:
			return t
		case []string:
			for i := len(t) - 1; i >= 0; i-- {
				if strings.TrimSpace(t[i]) != "" && t[i] != "-" {
					return t[i]
				}
			}
			return ""
		case []interface{}:
			for i := len(t) - 1; i >= 0; i-- {
				s := strings.TrimSpace(fmt.Sprintf("%v", t[i]))
				if s != "" && s != "-" && s != "<nil>" {
					return s
				}
			}
			return ""
		default:
			return fmt.Sprintf("%v", t)
		}
	}
	return ""
}

func fieldStringAny(m map[string]interface{}, keys ...string) string {
	for _, k := range keys {
		if v := fieldString(m, k); v != "" {
			return v
		}
	}
	return ""
}

package integration

import "time"

func parseTime(v string) time.Time {
	if v == "" {
		return time.Time{}
	}
	// Try RFC3339 first
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t
	}
	// Try unix seconds in string
	if ts, err := time.Parse("2006-01-02 15:04:05", v); err == nil {
		return ts
	}
	return time.Time{}
}

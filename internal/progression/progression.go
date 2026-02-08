package progression

import (
	"strings"
	"time"

	"aegisr/internal/env"
	"aegisr/internal/model"
	"aegisr/internal/state"
)

func Normalize(events []model.Event, environment env.Environment) []model.Envelope {
	hostZone := map[string]string{}
	hostCritical := map[string]bool{}
	for _, h := range environment.Hosts {
		hostZone[h.ID] = h.Zone
		hostCritical[h.ID] = h.Critical
	}
	out := make([]model.Envelope, 0, len(events))
	for _, e := range events {
		tags := []string{}
		if z := hostZone[e.Host]; z != "" {
			tags = append(tags, "zone:"+z)
		}
		if hostCritical[e.Host] {
			tags = append(tags, "critical")
		}
		source := getString(e.Details, "source", "unknown")
		confidence := getFloat(e.Details, "confidence", 0.5)
		evidence := []string{}
		if e.ID != "" {
			evidence = append(evidence, e.ID)
		}
		if ev, ok := e.Details["evidence"]; ok {
			if s, ok := ev.(string); ok {
				evidence = append(evidence, s)
			}
		}
		out = append(out, model.Envelope{
			Timestamp:  e.Time,
			Source:     source,
			Principal:  e.User,
			Asset:      e.Host,
			Action:     e.Type,
			Evidence:   evidence,
			Confidence: confidence,
			Tags:       tags,
		})
	}
	return out
}

func Update(envelopes []model.Envelope, st *state.AttackState) {
	if st.Progression == nil {
		st.Progression = []state.ProgressEvent{}
	}
	for _, env := range envelopes {
		stage, rationale := classify(env.Action)
		if stage == "" {
			continue
		}
		st.Progression = append(st.Progression, state.ProgressEvent{
			Time:       env.Timestamp,
			Source:     env.Source,
			Principal:  env.Principal,
			Asset:      env.Asset,
			Action:     env.Action,
			Confidence: env.Confidence,
			Stage:      stage,
			Rationale:  rationale,
		})
		// Update current position and compromised sets
		if env.Principal != "" {
			st.CompromisedUsers[env.Principal] = true
		}
		if env.Asset != "" {
			st.CompromisedHosts[env.Asset] = true
		}
		if env.Principal != "" && !contains(st.Position.Principals, env.Principal) {
			st.Position.Principals = append(st.Position.Principals, env.Principal)
		}
		if env.Asset != "" && !contains(st.Position.Assets, env.Asset) {
			st.Position.Assets = append(st.Position.Assets, env.Asset)
		}
		if env.Timestamp.After(st.Position.UpdatedAt) {
			st.Position.Stage = stage
			st.Position.Confidence = env.Confidence
			st.Position.UpdatedAt = env.Timestamp
		}
	}
}

func ApplyWindowAndDecay(st *state.AttackState, window time.Duration) {
	events := make([]ProgressEventLike, 0, len(st.Progression))
	for i := range st.Progression {
		events = append(events, &st.Progression[i])
	}
	events = ApplyDecay(events, time.Now().UTC(), window)
	// prune
	pruned := []state.ProgressEvent{}
	for _, e := range events {
		if pe, ok := e.(*state.ProgressEvent); ok {
			pruned = append(pruned, *pe)
		}
	}
	st.Progression = pruned
}

func classify(action string) (string, string) {
	a := strings.ToLower(action)
	// Identity / Auth
	if containsAny(a, []string{"new_geo_login", "impossible_travel", "mfa_disabled", "mfa_bypass", "mfa_reset", "token_refresh_anomaly", "token_creation_anomaly", "iam_change", "new_admin_account"}) {
		return "identity_auth", "Identity/auth progression signal"
	}
	// Host / Execution
	if containsAny(a, []string{"process_creation", "lolbin", "encoded_ps", "rundll32", "mshta", "lsass_access", "keychain_access", "scheduled_task", "service_install", "registry_change", "remote_exec", "psexec", "wmi", "winrm", "ssh_new_key"}) {
		return "host_execution", "Host execution/persistence signal"
	}
	// Lateral / Network
	if containsAny(a, []string{"rdp", "smb", "winrm", "ssh", "east_west_connection", "security_group_open", "firewall_rule_open"}) {
		return "lateral_network", "Lateral movement/network signal"
	}
	// Data / Impact
	if containsAny(a, []string{"bulk_download", "archive_encrypt", "exfil_tooling", "rclone", "mega"}) {
		return "data_impact", "Data access/exfiltration signal"
	}
	return "", ""
}

func containsAny(s string, list []string) bool {
	for _, v := range list {
		if strings.Contains(s, v) {
			return true
		}
	}
	return false
}

func contains(list []string, v string) bool {
	for _, item := range list {
		if item == v {
			return true
		}
	}
	return false
}

func getString(m map[string]interface{}, key string, fallback string) string {
	if m == nil {
		return fallback
	}
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return fallback
}

func getFloat(m map[string]interface{}, key string, fallback float64) float64 {
	if m == nil {
		return fallback
	}
	if v, ok := m[key]; ok {
		switch t := v.(type) {
		case float64:
			return t
		case int:
			return float64(t)
		}
	}
	return fallback
}

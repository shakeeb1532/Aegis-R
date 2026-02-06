package core

import (
	"fmt"
	"sort"
	"time"

	"aegisr/internal/env"
	"aegisr/internal/logic"
	"aegisr/internal/model"
	"aegisr/internal/ops"
	"aegisr/internal/progression"
	"aegisr/internal/state"
)

type Output struct {
	GeneratedAt  time.Time             `json:"generated_at"`
	Summary      string                `json:"summary"`
	Reasoning    model.ReasoningReport `json:"reasoning"`
	State        state.AttackState     `json:"state"`
	NextMoves    []string              `json:"next_moves"`
	DriftSignals []string              `json:"drift_signals"`
	Findings     []string              `json:"findings"`
}

func Assess(events []model.Event, rules []logic.Rule, environment env.Environment, st state.AttackState) Output {
	return AssessWithMetrics(events, rules, environment, st, nil, true)
}

func AssessWithMetrics(events []model.Event, rules []logic.Rule, environment env.Environment, st state.AttackState, metrics *ops.Metrics, includeEvidence bool) Output {
	if metrics != nil {
		metrics.IncEvents(len(events))
	}
	rep := logic.ReasonWithMetrics(events, rules, metrics, includeEvidence)
	st.UpdatedAt = time.Now().UTC()

	envelopes := progression.Normalize(events, environment)
	progression.Update(envelopes, &st)
	progression.ApplyWindowAndDecay(&st, 24*time.Hour)
	progression.OverlayGraph(environment, &st)

	index := make(map[string][]model.Event)
	for _, e := range events {
		index[e.Type] = append(index[e.Type], e)
	}

	// Mark compromised hosts/users based on strong signals
	for _, e := range index["beacon_outbound"] {
		if e.Host != "" {
			st.CompromisedHosts[e.Host] = true
			st.ReasoningChain = append(st.ReasoningChain, fmt.Sprintf("C2 beacon from %s implies host compromise", e.Host))
		}
	}
	for _, e := range index["lsass_access"] {
		if e.User != "" {
			st.CompromisedUsers[e.User] = true
			st.ReasoningChain = append(st.ReasoningChain, fmt.Sprintf("LSASS access by %s implies credential exposure", e.User))
		}
	}
	for _, e := range index["remote_service_creation"] {
		if e.Host != "" {
			st.CompromisedHosts[e.Host] = true
			st.ReasoningChain = append(st.ReasoningChain, fmt.Sprintf("Remote service creation on %s implies host compromise", e.Host))
		}
	}

	// Reachability across trust boundaries
	zoneOf := map[string]string{}
	for _, h := range environment.Hosts {
		zoneOf[h.ID] = h.Zone
		if st.CompromisedHosts[h.ID] {
			st.ReachableHosts[h.ID] = true
		}
	}

	graph := env.BuildGraph(environment)
	startZones := zonesFromReachable(st.ReachableHosts, zoneOf)
	reachableZones := graph.ReachableFrom(startZones)
	for z := range reachableZones {
		if zone := trimPrefix(z, "zone:"); zone != "" {
			if markZoneReachable(st.ReachableHosts, zoneOf, zone) {
				st.ReasoningChain = append(st.ReasoningChain, fmt.Sprintf("Reachability expanded to zone %s via trust graph", zone))
			}
		}
	}

	// Drift signals
	drift := []string{}
	if len(index["trust_boundary_change"]) > 0 {
		drift = append(drift, "Trust boundary configuration changed")
	}
	if len(index["identity_priv_change"]) > 0 {
		drift = append(drift, "Identity privilege levels changed")
	}
	if len(index["new_admin_account"]) > 0 {
		drift = append(drift, "New admin account created")
	}
	if len(index["policy_override"]) > 0 {
		drift = append(drift, "Policy override detected")
	}

	// Evidence gaps -> findings
	findings := make([]string, 0, len(rep.Results))
	for _, r := range rep.Results {
		if !r.Feasible && len(r.MissingEvidence) > 0 {
			findings = append(findings, fmt.Sprintf("%s incomplete: missing %d evidence types", r.RuleID, len(r.MissingEvidence)))
		}
		if r.Feasible {
			findings = append(findings, fmt.Sprintf("%s feasible with confidence %.2f", r.RuleID, r.Confidence))
		}
	}
	if metrics != nil {
		metrics.IncFindings(len(findings))
	}

	// Predict next moves: reachable but uncompromised critical hosts
	next := make([]string, 0, len(environment.Hosts)+len(environment.Identities))
	for _, h := range environment.Hosts {
		if st.ReachableHosts[h.ID] && !st.CompromisedHosts[h.ID] {
			if h.Critical {
				next = append(next, fmt.Sprintf("Likely lateral movement to critical host %s", h.ID))
			} else {
				next = append(next, fmt.Sprintf("Possible lateral movement to host %s", h.ID))
			}
		}
	}
	for _, id := range environment.Identities {
		if id.PrivLevel == "high" && !st.CompromisedUsers[id.ID] {
			next = append(next, fmt.Sprintf("Privilege escalation target: identity %s", id.ID))
		}
	}

	sort.Strings(next)

	return Output{
		GeneratedAt:  time.Now().UTC(),
		Summary:      "Causal feasibility, progression state, and evidence gaps evaluated.",
		Reasoning:    rep,
		State:        st,
		NextMoves:    next,
		DriftSignals: drift,
		Findings:     findings,
	}
}

func zoneReachable(reachable map[string]bool, zoneOf map[string]string, zone string) bool {
	for host, ok := range reachable {
		if ok && zoneOf[host] == zone {
			return true
		}
	}
	return false
}

func markZoneReachable(reachable map[string]bool, zoneOf map[string]string, zone string) bool {
	changed := false
	for host, z := range zoneOf {
		if z == zone && !reachable[host] {
			reachable[host] = true
			changed = true
		}
	}
	return changed
}

func zonesFromReachable(reachable map[string]bool, zoneOf map[string]string) []string {
	out := []string{}
	seen := map[string]bool{}
	for host, ok := range reachable {
		if ok {
			z := zoneOf[host]
			key := "zone:" + z
			if !seen[key] {
				seen[key] = true
				out = append(out, key)
			}
		}
	}
	return out
}

func trimPrefix(val string, prefix string) string {
	if len(val) >= len(prefix) && val[:len(prefix)] == prefix {
		return val[len(prefix):]
	}
	return ""
}

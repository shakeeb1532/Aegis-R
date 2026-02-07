package core

import (
	"fmt"
	"sort"
	"strings"
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

	reqs := map[string][]string{}
	for _, r := range rules {
		types := make([]string, 0, len(r.Requirements))
		for _, req := range r.Requirements {
			types = append(types, req.Type)
		}
		reqs[r.ID] = types
	}
	eventIndex := map[string][]model.Event{}
	for _, e := range events {
		eventIndex[e.Type] = append(eventIndex[e.Type], e)
	}

	applyDecisionCacheAndThreads(&rep, events, &st, reqs, eventIndex)

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

const decisionCacheTTL = 24 * time.Hour
const threadWindow = 2 * time.Hour

func applyDecisionCacheAndThreads(rep *model.ReasoningReport, events []model.Event, st *state.AttackState, reqs map[string][]string, index map[string][]model.Event) {
	if st.DecisionCache == nil {
		st.DecisionCache = state.DecisionCache{}
	}
	if st.Tickets == nil {
		st.Tickets = []state.Ticket{}
	}
	now := time.Now().UTC()
	for i := range rep.Results {
		r := &rep.Results[i]
		host, principal, lastSeen, conf, threadReason := deriveContext(r, events, reqs, index)
		r.ThreadConfidence = conf
		r.ThreadReason = threadReason
		threadID := upsertThread(st, host, principal, lastSeen, r.RuleID, conf, threadReason)
		if threadID != "" {
			r.ThreadID = threadID
		}
		key := cacheKey(host, principal, r.RuleID)
		label := r.DecisionLabel
		reasonCode := r.ReasonCode
		if label == "" || reasonCode == "" {
			autoLabel, autoReason := decisionLabel(r, host, principal)
			if label == "" {
				label = autoLabel
			}
			if reasonCode == "" && autoReason != "" {
				reasonCode = autoReason
			}
		}
		cacheHit := false
		if entry, ok := st.DecisionCache[key]; ok {
			if now.Sub(entry.UpdatedAt) <= decisionCacheTTL {
				cacheHit = true
				if r.Feasible {
					label = "escalate"
				} else if label == "keep" {
					label = "deprioritize"
				}
				reasonCode = "policy_override"
			}
		}
		r.DecisionLabel = label
		r.CacheHit = cacheHit
		if r.ReasonCode == "" {
			r.ReasonCode = reasonCode
		}
		st.DecisionCache[key] = state.DecisionCacheEntry{
			Host:        host,
			Principal:   principal,
			RuleID:      r.RuleID,
			Verdict:     verdictForRule(r),
			Label:       r.DecisionLabel,
			ReasonCode:  r.ReasonCode,
			UpdatedAt:   now,
			EvidenceIDs: r.SupportingEventIDs,
		}
		if threadID != "" {
			upsertTicket(st, threadID, host, principal, r)
		}
	}
}

func decisionLabel(r *model.RuleResult, host string, principal string) (string, string) {
	if r.Feasible {
		if host == "" && principal == "" {
			return "escalate", "environment_unknown"
		}
		return "escalate", ""
	}
	if !r.PrecondOK {
		if host == "" && principal == "" {
			return "keep", "environment_unknown"
		}
		return "keep", "precond_missing"
	}
	if len(r.MissingEvidence) > 0 {
		if host == "" && principal == "" {
			return "deprioritize", "environment_unknown"
		}
		if r.PrecondOK {
			return "deprioritize", "evidence_gap"
		}
		return "keep", "precond_missing"
	}
	return "suppress", "insufficient_telemetry"
}

func deriveContext(r *model.RuleResult, events []model.Event, reqs map[string][]string, index map[string][]model.Event) (string, string, time.Time, float64, string) {
	host, principal, last, ok := pickContext(r.SupportingEvents)
	if ok {
		return host, principal, last, 1.0, "supporting_evidence"
	}
	if types, ok := reqs[r.RuleID]; ok {
		filtered := []model.Event{}
		for _, t := range types {
			filtered = append(filtered, index[t]...)
		}
		host, principal, last, ok = pickContext(filtered)
		if ok {
			return host, principal, last, 0.7, "rule_evidence"
		}
	}
	// If evidence is ambiguous, only fall back when the entire event set
	// has a single unique host/principal pair.
	host, principal, last, ok = pickContext(events)
	if ok {
		return host, principal, last, 0.4, "global_singleton"
	}
	if len(events) == 0 {
		return "", "", time.Time{}, 0, "missing_context"
	}
	return "", "", time.Time{}, 0, "ambiguous_context"
}

func pickContext(events []model.Event) (string, string, time.Time, bool) {
	hosts := map[string]bool{}
	users := map[string]bool{}
	var last time.Time
	for _, ev := range events {
		if ev.Host != "" {
			hosts[ev.Host] = true
		}
		if ev.User != "" {
			users[ev.User] = true
		}
		if ev.Time.After(last) {
			last = ev.Time
		}
	}
	if len(hosts) != 1 || len(users) != 1 {
		return "", "", time.Time{}, false
	}
	var host, user string
	for h := range hosts {
		host = h
	}
	for u := range users {
		user = u
	}
	if last.IsZero() {
		return "", "", time.Time{}, false
	}
	return host, user, last, true
}

func cacheKey(host string, principal string, ruleID string) string {
	return strings.Join([]string{host, principal, ruleID}, "|")
}

func verdictForRule(r *model.RuleResult) string {
	if r.Feasible {
		return "confirmed"
	}
	if len(r.MissingEvidence) > 0 {
		return "incomplete"
	}
	return "impossible"
}

func upsertThread(st *state.AttackState, host string, principal string, when time.Time, ruleID string, confidence float64, reason string) string {
	if host == "" && principal == "" {
		return ""
	}
	if when.IsZero() {
		when = time.Now().UTC()
	}
	for i := range st.Threads {
		t := &st.Threads[i]
		if t.Host == host && t.Principal == principal {
			if when.Sub(t.LastSeen) <= threadWindow {
				if when.Before(t.FirstSeen) {
					t.FirstSeen = when
				}
				if when.After(t.LastSeen) {
					t.LastSeen = when
				}
				if !containsRule(t.RuleIDs, ruleID) && ruleID != "" {
					t.RuleIDs = append(t.RuleIDs, ruleID)
					sort.Strings(t.RuleIDs)
				}
				if confidence > t.Confidence {
					t.Confidence = confidence
					t.Reason = reason
				}
				return t.ID
			}
		}
	}
	id := fmt.Sprintf("thread-%d", time.Now().UTC().UnixNano())
	rules := []string{}
	if ruleID != "" {
		rules = append(rules, ruleID)
	}
	st.Threads = append(st.Threads, state.Thread{
		ID:         id,
		Host:       host,
		Principal:  principal,
		FirstSeen:  when,
		LastSeen:   when,
		RuleIDs:    rules,
		Confidence: confidence,
		Reason:     reason,
	})
	return id
}

func upsertTicket(st *state.AttackState, threadID string, host string, principal string, r *model.RuleResult) {
	now := time.Now().UTC()
	for i := range st.Tickets {
		t := &st.Tickets[i]
		if t.ThreadID == threadID {
			t.UpdatedAt = now
			if !containsRule(t.RuleIDs, r.RuleID) && r.RuleID != "" {
				t.RuleIDs = append(t.RuleIDs, r.RuleID)
				sort.Strings(t.RuleIDs)
			}
			t.DecisionLabel = mostSevereLabel(t.DecisionLabel, r.DecisionLabel)
			if t.ReasonCode == "" {
				t.ReasonCode = r.ReasonCode
			}
			t.Status = statusFromLabel(t.Status, t.DecisionLabel)
			return
		}
	}
	id := fmt.Sprintf("ticket-%d", time.Now().UTC().UnixNano())
	st.Tickets = append(st.Tickets, state.Ticket{
		ID:            id,
		ThreadID:      threadID,
		Host:          host,
		Principal:     principal,
		Status:        statusFromLabel("", r.DecisionLabel),
		DecisionLabel: r.DecisionLabel,
		ReasonCode:    r.ReasonCode,
		CreatedAt:     now,
		UpdatedAt:     now,
		RuleIDs:       filterRuleIDs([]string{r.RuleID}),
	})
}

func mostSevereLabel(a string, b string) string {
	rank := map[string]int{
		"suppress":     1,
		"deprioritize": 2,
		"keep":         3,
		"escalate":     4,
	}
	if rank[b] > rank[a] {
		return b
	}
	if a == "" {
		return b
	}
	return a
}

func statusFromLabel(current string, label string) string {
	switch label {
	case "escalate":
		return "in_review"
	case "suppress":
		if current == "in_review" {
			return current
		}
		return "closed"
	case "deprioritize", "keep":
		if current == "" {
			return "open"
		}
		return current
	default:
		if current == "" {
			return "open"
		}
		return current
	}
}

func filterRuleIDs(list []string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, v := range list {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

func containsRule(list []string, rule string) bool {
	for _, v := range list {
		if v == rule {
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

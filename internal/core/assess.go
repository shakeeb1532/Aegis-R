package core

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"aman/internal/env"
	"aman/internal/logic"
	"aman/internal/model"
	"aman/internal/ops"
	"aman/internal/progression"
	"aman/internal/state"
)

type Output struct {
	GeneratedAt  time.Time             `json:"generated_at"`
	Summary      string                `json:"summary"`
	Notices      []string              `json:"notices,omitempty"`
	Reasoning    model.ReasoningReport `json:"reasoning"`
	State        state.AttackState     `json:"state"`
	NextMoves    []string              `json:"next_moves"`
	DriftSignals []string              `json:"drift_signals"`
	Findings     []string              `json:"findings"`
}

type RuntimeOptions struct {
	Now           time.Time
	Deterministic bool
}

func DefaultRuntimeOptions() RuntimeOptions {
	return RuntimeOptions{Now: time.Now().UTC()}
}

func Assess(events []model.Event, rules []logic.Rule, environment env.Environment, st state.AttackState) Output {
	return AssessWithOptions(events, rules, environment, st, nil, true, DefaultRuntimeOptions())
}

func AssessWithMetrics(events []model.Event, rules []logic.Rule, environment env.Environment, st state.AttackState, metrics *ops.Metrics, includeEvidence bool) Output {
	return AssessWithOptions(events, rules, environment, st, metrics, includeEvidence, DefaultRuntimeOptions())
}

func AssessWithOptions(events []model.Event, rules []logic.Rule, environment env.Environment, st state.AttackState, metrics *ops.Metrics, includeEvidence bool, runtime RuntimeOptions) Output {
	if runtime.Now.IsZero() {
		runtime.Now = time.Now().UTC()
	}
	if runtime.Deterministic {
		events = stableEvents(events)
	}
	if metrics != nil {
		metrics.IncEvents(len(events))
	}
	cfg := logic.DefaultReasonerConfig()
	cfg.Now = func() time.Time { return runtime.Now }
	rep := logic.ReasonWithEnvAndMetricsWithConfig(events, rules, environment, metrics, includeEvidence, cfg)
	st.UpdatedAt = runtime.Now

	envelopes := progression.Normalize(events, environment)
	progression.Update(envelopes, &st)
	progression.ApplyWindowAndDecayAt(&st, runtime.Now, 24*time.Hour)
	progression.OverlayGraph(environment, &st)
	if runtime.Deterministic {
		sort.Strings(st.GraphOverlay.CurrentNodes)
		sort.Strings(st.GraphOverlay.Reachable)
		sort.Strings(st.Position.Principals)
		sort.Strings(st.Position.Assets)
		sort.Strings(st.Signals)
	}

	eventIndex := make(map[string][]int, 64)
	for i, e := range events {
		eventIndex[e.Type] = append(eventIndex[e.Type], i)
	}

	// Mark compromised hosts/users based on strong signals
	for _, idx := range eventIndex["beacon_outbound"] {
		e := events[idx]
		if e.Host != "" {
			st.CompromisedHosts[e.Host] = true
			st.ReasoningChain = append(st.ReasoningChain, fmt.Sprintf("C2 beacon from %s implies host compromise", e.Host))
		}
	}
	for _, idx := range eventIndex["lsass_access"] {
		e := events[idx]
		if e.User != "" {
			st.CompromisedUsers[e.User] = true
			st.ReasoningChain = append(st.ReasoningChain, fmt.Sprintf("LSASS access by %s implies credential exposure", e.User))
		}
	}
	for _, idx := range eventIndex["remote_service_creation"] {
		e := events[idx]
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

	activeFacts := logic.ActiveFactsFromIndex(events, eventIndex)
	graph := env.BuildGraph(environment, activeFacts)
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
	if len(eventIndex["trust_boundary_change"]) > 0 {
		drift = append(drift, "Trust boundary configuration changed")
	}
	if len(eventIndex["identity_priv_change"]) > 0 {
		drift = append(drift, "Identity privilege levels changed")
	}
	if len(eventIndex["new_admin_account"]) > 0 {
		drift = append(drift, "New admin account created")
	}
	if len(eventIndex["policy_override"]) > 0 {
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
	applyDecisionCacheAndThreads(&rep, events, &st, reqs, eventIndex, runtime)

	return Output{
		GeneratedAt:  runtime.Now,
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
const decisionCacheMaxEntries = 5000
const maxThreadsPerWindow = 2000

func applyDecisionCacheAndThreads(rep *model.ReasoningReport, events []model.Event, st *state.AttackState, reqs map[string][]string, index map[string][]int, runtime RuntimeOptions) {
	if st.DecisionCache == nil {
		st.DecisionCache = state.DecisionCache{}
	}
	if st.Tickets == nil {
		st.Tickets = []state.Ticket{}
	}
	now := runtime.Now
	for i := range rep.Results {
		r := &rep.Results[i]
		host, principal, lastSeen, conf, threadReason := deriveContext(r, events, reqs, index)
		r.ThreadConfidence = conf
		r.ThreadReason = threadReason
		threadID := upsertThread(st, host, principal, lastSeen, r.RuleID, r.Name, conf, threadReason, runtime)
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
				if r.Conflicted {
					label = "keep"
					reasonCode = "conflicted"
				} else if r.Feasible {
					label = "escalate"
				} else if label == "keep" {
					label = "deprioritize"
				}
				if reasonCode == "" {
					reasonCode = "policy_override"
				}
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
			upsertTicket(st, threadID, host, principal, r, runtime)
		}
	}
	pruneDecisionCache(st.DecisionCache, now)
	pruneThreadsAndTickets(st, now)
}

func pruneDecisionCache(cache state.DecisionCache, now time.Time) {
	if len(cache) == 0 {
		return
	}
	for key, entry := range cache {
		if now.Sub(entry.UpdatedAt) > decisionCacheTTL {
			delete(cache, key)
		}
	}
	if len(cache) <= decisionCacheMaxEntries {
		return
	}
	type item struct {
		key string
		at  time.Time
	}
	items := make([]item, 0, len(cache))
	for k, v := range cache {
		items = append(items, item{key: k, at: v.UpdatedAt})
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].at.Before(items[j].at)
	})
	excess := len(items) - decisionCacheMaxEntries
	for i := 0; i < excess; i++ {
		delete(cache, items[i].key)
	}
}

func pruneThreadsAndTickets(st *state.AttackState, now time.Time) {
	if len(st.Threads) == 0 {
		return
	}
	if len(st.Threads) > maxThreadsPerWindow {
		sort.Slice(st.Threads, func(i, j int) bool {
			return st.Threads[i].LastSeen.Before(st.Threads[j].LastSeen)
		})
		st.Threads = st.Threads[len(st.Threads)-maxThreadsPerWindow:]
	}
	if len(st.Tickets) == 0 {
		return
	}
	threadIDs := map[string]bool{}
	for _, t := range st.Threads {
		threadIDs[t.ID] = true
	}
	tickets := st.Tickets[:0]
	for _, tk := range st.Tickets {
		if !threadIDs[tk.ThreadID] {
			continue
		}
		tickets = append(tickets, tk)
	}
	st.Tickets = tickets
}

func decisionLabel(r *model.RuleResult, host string, principal string) (string, string) {
	if r.PolicyImpossible {
		return "suppress", "policy_impossible"
	}
	if r.Conflicted {
		return "keep", "conflicted"
	}
	if r.ReasonCode == "telemetry_gap_high_signal" {
		return "keep", "telemetry_gap_high_signal"
	}
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
		if hasMissingPreconds(r.MissingEvidence) {
			if host == "" && principal == "" {
				return "keep", "environment_unknown"
			}
			return "keep", "evidence_gap"
		}
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

func hasMissingPreconds(reqs []model.EvidenceRequirement) bool {
	for _, req := range reqs {
		if strings.HasPrefix(req.Type, "precond:") || strings.HasPrefix(req.Type, "precond_order:") || strings.HasPrefix(req.Type, "precond_order_ambiguous:") || strings.HasPrefix(req.Type, "precond_any:") || req.Type == "environment_context" {
			return true
		}
	}
	return false
}

func deriveContext(r *model.RuleResult, events []model.Event, reqs map[string][]string, index map[string][]int) (string, string, time.Time, float64, string) {
	host, principal, last, ok := pickContext(r.SupportingEvents)
	if ok {
		return host, principal, last, 1.0, "supporting_evidence"
	}
	if types, ok := reqs[r.RuleID]; ok {
		idxs := make([]int, 0, 8)
		for _, t := range types {
			idxs = append(idxs, index[t]...)
		}
		host, principal, last, ok = pickContextIndices(events, idxs)
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
	var host, user string
	var last time.Time
	seenHost := false
	seenUser := false
	for _, ev := range events {
		if ev.Host != "" {
			if !seenHost {
				host = ev.Host
				seenHost = true
			} else if ev.Host != host {
				return "", "", time.Time{}, false
			}
		}
		if ev.User != "" {
			if !seenUser {
				user = ev.User
				seenUser = true
			} else if ev.User != user {
				return "", "", time.Time{}, false
			}
		}
		if ev.Time.After(last) {
			last = ev.Time
		}
	}
	if !seenHost || !seenUser || last.IsZero() {
		return "", "", time.Time{}, false
	}
	return host, user, last, true
}

func pickContextIndices(events []model.Event, idxs []int) (string, string, time.Time, bool) {
	var host, user string
	var last time.Time
	seenHost := false
	seenUser := false
	for _, idx := range idxs {
		if idx < 0 || idx >= len(events) {
			continue
		}
		ev := events[idx]
		if ev.Host != "" {
			if !seenHost {
				host = ev.Host
				seenHost = true
			} else if ev.Host != host {
				return "", "", time.Time{}, false
			}
		}
		if ev.User != "" {
			if !seenUser {
				user = ev.User
				seenUser = true
			} else if ev.User != user {
				return "", "", time.Time{}, false
			}
		}
		if ev.Time.After(last) {
			last = ev.Time
		}
	}
	if !seenHost || !seenUser || last.IsZero() {
		return "", "", time.Time{}, false
	}
	return host, user, last, true
}

func cacheKey(host string, principal string, ruleID string) string {
	return strings.Join([]string{host, principal, ruleID}, "|")
}

func verdictForRule(r *model.RuleResult) string {
	if r.PolicyImpossible {
		return "impossible"
	}
	if r.Conflicted {
		return "conflicted"
	}
	if r.Feasible {
		return "confirmed"
	}
	if len(r.MissingEvidence) > 0 {
		return "incomplete"
	}
	return "incomplete"
}

func upsertThread(st *state.AttackState, host string, principal string, when time.Time, ruleID string, ruleName string, confidence float64, reason string, runtime RuntimeOptions) string {
	if host == "" && principal == "" {
		return ""
	}
	if when.IsZero() {
		when = runtime.Now
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
				if t.Title == "" {
					t.Title = buildThreadTitle(host, principal, ruleName, ruleID)
				}
				return t.ID
			}
		}
	}
	id := newThreadID(host, principal, when, runtime)
	rules := []string{}
	if ruleID != "" {
		rules = append(rules, ruleID)
	}
	st.Threads = append(st.Threads, state.Thread{
		ID:         id,
		Title:      buildThreadTitle(host, principal, ruleName, ruleID),
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

func upsertTicket(st *state.AttackState, threadID string, host string, principal string, r *model.RuleResult, runtime RuntimeOptions) {
	now := runtime.Now
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
			if t.Title == "" {
				t.Title = buildTicketTitle(host, principal, r.Name, r.RuleID)
			}
			t.Status = statusFromLabel(t.Status, t.DecisionLabel)
			return
		}
	}
	id := newTicketID(threadID, host, principal, runtime)
	st.Tickets = append(st.Tickets, state.Ticket{
		ID:            id,
		Title:         buildTicketTitle(host, principal, r.Name, r.RuleID),
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

func buildThreadTitle(host string, principal string, ruleName string, ruleID string) string {
	subject := firstNonEmptyString(host, principal, "environment")
	activity := cleanRuleTitle(ruleName, ruleID)
	if activity == "" {
		return "Reasoning thread for " + subject
	}
	return activity + " on " + subject
}

func buildTicketTitle(host string, principal string, ruleName string, ruleID string) string {
	subject := firstNonEmptyString(host, principal, "environment")
	activity := cleanRuleTitle(ruleName, ruleID)
	if activity == "" {
		return "Review security decision for " + subject
	}
	return "Review " + activity + " on " + subject
}

func cleanRuleTitle(ruleName string, ruleID string) string {
	title := strings.TrimSpace(ruleName)
	if title == "" {
		title = strings.TrimSpace(ruleID)
	}
	title = strings.TrimSuffix(title, " (preconditions unmet)")
	title = strings.TrimSuffix(title, " (context missing)")
	title = strings.TrimSuffix(title, " (env: target unreachable)")
	title = strings.TrimSuffix(title, " (env: insufficient privilege)")
	title = strings.TrimSuffix(title, " (policy impossible)")
	return strings.TrimSpace(title)
}

func firstNonEmptyString(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func newThreadID(host string, principal string, when time.Time, runtime RuntimeOptions) string {
	if !runtime.Deterministic {
		return fmt.Sprintf("thread-%d", time.Now().UTC().UnixNano())
	}
	windowStart := when.Truncate(threadWindow).UTC().Format(time.RFC3339)
	sum := sha256.Sum256([]byte(host + "|" + principal + "|" + windowStart))
	return "thread-" + hex.EncodeToString(sum[:8])
}

func newTicketID(threadID string, host string, principal string, runtime RuntimeOptions) string {
	if !runtime.Deterministic {
		return fmt.Sprintf("ticket-%d", time.Now().UTC().UnixNano())
	}
	sum := sha256.Sum256([]byte(threadID + "|" + host + "|" + principal))
	return "ticket-" + hex.EncodeToString(sum[:8])
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

func stableEvents(events []model.Event) []model.Event {
	out := append([]model.Event(nil), events...)
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].Time.Equal(out[j].Time) {
			return out[i].Time.Before(out[j].Time)
		}
		if out[i].ID != out[j].ID {
			return out[i].ID < out[j].ID
		}
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		return out[i].User < out[j].User
	})
	return out
}

package logic

import (
	"strings"
	"time"

	"aman/internal/model"
)

type causalFact struct {
	Observed bool
	At       time.Time
}

type precondOrder int

const (
	precondOrderOK precondOrder = iota
	precondOrderAmbiguous
	precondOrderViolated
)

func ActiveFacts(events []model.Event) map[string]bool {
	index := make(map[string][]int, 64)
	for i, e := range events {
		index[e.Type] = append(index[e.Type], i)
	}
	return ActiveFactsFromIndex(events, index)
}

func ActiveFactsFromIndex(events []model.Event, index map[string][]int) map[string]bool {
	facts := deriveCausalFacts(events, index)
	return activeFactsFromCausal(facts)
}

func deriveCausalFacts(events []model.Event, index map[string][]int) map[string]causalFact {
	facts := map[string]causalFact{}
	emailAt, hasEmail := earliestEventTime(events, index["email_attachment_open"])
	macroAt, hasMacro := earliestEventTime(events, index["macro_execution"])
	initialAt := time.Time{}
	if hasEmail && hasMacro && !macroAt.Before(emailAt) {
		initialAt = macroAt
	}
	if t, ok := earliestAnyEventTime(events, index, "token_reuse", "exploit_kit_hit", "web_exploit_hit"); ok {
		if initialAt.IsZero() || t.Before(initialAt) {
			initialAt = t
		}
	}
	phishAt, hasPhish := earliestEventTime(events, index["phish_link_click"])
	consentAt, hasConsent := earliestEventTime(events, index["oauth_consent"])
	if hasPhish && hasConsent {
		phishChain := maxTime(phishAt, consentAt)
		if initialAt.IsZero() || phishChain.Before(initialAt) {
			initialAt = phishChain
		}
	}
	if !initialAt.IsZero() {
		facts["initial_access"] = causalFact{Observed: true, At: initialAt}
	}

	tokenAt, hasToken := earliestEventTime(events, index["token_manipulation"])
	adminAt, hasAdmin := earliestEventTime(events, index["admin_group_change"])
	if hasToken && hasAdmin {
		facts["privilege_escalation"] = causalFact{Observed: true, At: maxTime(tokenAt, adminAt)}
	} else if hasToken {
		facts["privilege_escalation"] = causalFact{Observed: true, At: tokenAt}
	} else if hasAdmin {
		facts["privilege_escalation"] = causalFact{Observed: true, At: adminAt}
	}

	if t, ok := earliestAnyEventTime(events, index,
		"lsass_access",
		"ntds_dit_access",
		"credential_dumping",
		"sam_database_access",
		"keychain_access",
	); ok {
		facts["credential_access"] = causalFact{Observed: true, At: t}
	} else if t, ok := earliestCredentialToolExecution(events, index["process_creation"]); ok {
		facts["credential_access"] = causalFact{Observed: true, At: t}
	}

	beaconAt, hasBeacon := earliestEventTime(events, index["beacon_outbound"])
	dnsAt, hasDNS := earliestEventTime(events, index["dns_tunneling"])
	if hasBeacon && hasDNS {
		facts["c2_established"] = causalFact{Observed: true, At: minTime(beaconAt, dnsAt)}
	} else if hasBeacon {
		facts["c2_established"] = causalFact{Observed: true, At: beaconAt}
	} else if hasDNS {
		facts["c2_established"] = causalFact{Observed: true, At: dnsAt}
	}

	if t, ok := earliestAnyEventTime(events, index,
		"impossible_travel", "new_device_login",
	); ok {
		facts["identity_compromise"] = causalFact{Observed: true, At: t}
	} else if countObservedEventTypes(index,
		"oauth_consent", "new_app_grant", "device_code_flow_success", "device_join_complete",
	) >= 2 {
		if t, ok := earliestAnyEventTime(events, index,
			"oauth_consent", "new_app_grant", "device_code_flow_success", "device_join_complete",
		); ok {
			facts["identity_compromise"] = causalFact{Observed: true, At: t}
		}
	} else if countObservedEventTypes(index,
		"oauth_consent", "new_app_grant", "device_code_flow_success", "device_join_complete",
	) >= 1 && countObservedEventTypes(index,
		"token_refresh_anomaly", "mfa_method_removed", "mfa_policy_changed",
	) >= 1 {
		if t, ok := earliestAnyEventTime(events, index,
			"oauth_consent", "new_app_grant", "device_code_flow_success", "device_join_complete",
			"token_refresh_anomaly", "mfa_method_removed", "mfa_policy_changed",
		); ok {
			facts["identity_compromise"] = causalFact{Observed: true, At: t}
		}
	}
	if t, ok := earliestEventTime(events, index["signin_success"]); ok {
		facts["signin_success"] = causalFact{Observed: true, At: t}
	}

	return facts
}

func activeFactsFromCausal(facts map[string]causalFact) map[string]bool {
	active := map[string]bool{}
	for name, fact := range facts {
		if fact.Observed {
			active[name] = true
		}
	}
	return active
}

func preconditionGaps(
	rule Rule,
	facts map[string]causalFact,
	requirementAt time.Time,
	hasRequirementTime bool,
	orderingJitter time.Duration,
) []model.EvidenceRequirement {
	gaps := []model.EvidenceRequirement{}
	for _, p := range rule.Preconds {
		ok, orderStatus := precondSatisfied(p, facts, requirementAt, hasRequirementTime, orderingJitter)
		if !ok {
			kind := "precond:" + p
			desc := "Precondition not observed: " + p
			if orderStatus == precondOrderAmbiguous {
				kind = "precond_order_ambiguous:" + p
				desc = "Precondition ordering ambiguous within jitter window: " + p
			} else if orderStatus == precondOrderViolated {
				kind = "precond_order:" + p
				desc = "Precondition observed after dependent activity: " + p
			}
			gaps = append(gaps, model.EvidenceRequirement{
				Type:        kind,
				Description: desc,
			})
		}
	}
	for _, group := range rule.PrecondGroups {
		if len(group) == 0 {
			continue
		}
		groupOK := false
		for _, p := range group {
			ok, _ := precondSatisfied(p, facts, requirementAt, hasRequirementTime, orderingJitter)
			if ok {
				groupOK = true
				break
			}
		}
		if !groupOK {
			gaps = append(gaps, model.EvidenceRequirement{
				Type:        "precond_any:" + strings.Join(group, "|"),
				Description: "Missing any of preconditions: " + strings.Join(group, ", "),
			})
		}
	}
	return gaps
}

func precondSatisfied(name string, facts map[string]causalFact, requirementAt time.Time, hasRequirementTime bool, orderingJitter time.Duration) (bool, precondOrder) {
	f, ok := facts[name]
	if !ok || !f.Observed {
		return false, precondOrderOK
	}
	if hasRequirementTime && !f.At.IsZero() && f.At.After(requirementAt) {
		if orderingJitter > 0 && !f.At.After(requirementAt.Add(orderingJitter)) {
			return false, precondOrderAmbiguous
		}
		return false, precondOrderViolated
	}
	return true, precondOrderOK
}

func earliestRequirementTime(events []model.Event, index map[string][]int, rule Rule) (time.Time, bool) {
	var out time.Time
	found := false
	for _, req := range rule.Requirements {
		t, ok := earliestEventTime(events, index[req.Type])
		if !ok {
			continue
		}
		if !found || t.Before(out) {
			out = t
			found = true
		}
	}
	return out, found
}

func earliestEventTime(events []model.Event, idxs []int) (time.Time, bool) {
	var out time.Time
	found := false
	for _, idx := range idxs {
		t := events[idx].Time
		if t.IsZero() {
			continue
		}
		if !found || t.Before(out) {
			out = t
			found = true
		}
	}
	return out, found
}

func earliestAnyEventTime(events []model.Event, index map[string][]int, types ...string) (time.Time, bool) {
	var out time.Time
	found := false
	for _, typ := range types {
		t, ok := earliestEventTime(events, index[typ])
		if !ok {
			continue
		}
		if !found || t.Before(out) {
			out = t
			found = true
		}
	}
	return out, found
}

func minTime(a time.Time, b time.Time) time.Time {
	if a.IsZero() {
		return b
	}
	if b.IsZero() {
		return a
	}
	if a.Before(b) {
		return a
	}
	return b
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

func countObservedEventTypes(index map[string][]int, types ...string) int {
	count := 0
	for _, typ := range types {
		if len(index[typ]) > 0 {
			count++
		}
	}
	return count
}

func earliestCredentialToolExecution(events []model.Event, idxs []int) (time.Time, bool) {
	var out time.Time
	found := false
	for _, idx := range idxs {
		if idx < 0 || idx >= len(events) {
			continue
		}
		ev := events[idx]
		if !looksLikeCredentialAccessProcess(ev) {
			continue
		}
		t := ev.Time
		if t.IsZero() {
			continue
		}
		if !found || t.Before(out) {
			out = t
			found = true
		}
	}
	return out, found
}

func looksLikeCredentialAccessProcess(ev model.Event) bool {
	if ev.Type != "process_creation" && ev.Type != "process_start" {
		return false
	}
	if ev.Details == nil {
		return false
	}
	candidates := []string{
		detailString(ev.Details, "tool"),
		detailString(ev.Details, "image"),
		detailString(ev.Details, "process"),
		detailString(ev.Details, "command"),
		detailString(ev.Details, "command_line"),
		detailString(ev.Details, "cmd"),
	}
	for _, raw := range candidates {
		s := strings.ToLower(strings.TrimSpace(raw))
		if s == "" {
			continue
		}
		if strings.Contains(s, "mimikatz") ||
			strings.Contains(s, "procdump") ||
			strings.Contains(s, "lsassy") ||
			strings.Contains(s, "nanodump") ||
			strings.Contains(s, "secretsdump") ||
			strings.Contains(s, "comsvcs.dll") {
			return true
		}
	}
	return false
}

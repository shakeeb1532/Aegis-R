package logic

import (
	"time"

	"aman/internal/model"
)

type causalFact struct {
	Observed bool
	At       time.Time
}

func deriveCausalFacts(events []model.Event, index map[string][]int, cfg ReasonerConfig) map[string]causalFact {
	facts := map[string]causalFact{}
	emailAt, hasEmail := earliestEventTime(events, index["email_attachment_open"])
	macroAt, hasMacro := earliestEventTime(events, index["macro_execution"])
	if hasEmail && hasMacro && !macroAt.Before(emailAt) {
		facts["initial_access"] = causalFact{Observed: true, At: macroAt}
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

	lsassAt, hasLsass := earliestEventTime(events, index["lsass_access"])
	procAt, hasProc := earliestEventTime(events, index["process_creation"])
	if hasLsass {
		facts["credential_access"] = causalFact{Observed: true, At: lsassAt}
	} else if cfg.AllowProcessCreationAsCredentialAccess && hasProc {
		facts["credential_access"] = causalFact{Observed: true, At: procAt}
	}

	beaconAt, hasBeacon := earliestEventTime(events, index["beacon_outbound"])
	dnsAt, hasDNS := earliestEventTime(events, index["dns_tunneling"])
	if hasBeacon && hasDNS {
		facts["c2_established"] = causalFact{Observed: true, At: maxTime(beaconAt, dnsAt)}
	} else if hasBeacon {
		facts["c2_established"] = causalFact{Observed: true, At: beaconAt}
	} else if hasDNS {
		facts["c2_established"] = causalFact{Observed: true, At: dnsAt}
	}

	if t, ok := earliestAnyEventTime(events, index,
		"impossible_travel", "new_device_login", "mfa_disabled",
		"token_refresh_anomaly", "oauth_consent", "new_app_grant",
		"device_code_flow_success", "device_join_complete",
	); ok {
		facts["identity_compromise"] = causalFact{Observed: true, At: t}
	}
	if t, ok := earliestEventTime(events, index["valid_account_login"]); ok {
		facts["valid_account_login"] = causalFact{Observed: true, At: t}
	}

	return facts
}

func preconditionGaps(
	rule Rule,
	facts map[string]causalFact,
	requirementAt time.Time,
	hasRequirementTime bool,
) []model.EvidenceRequirement {
	gaps := []model.EvidenceRequirement{}
	for _, p := range rule.Preconds {
		f, ok := facts[p]
		if !ok || !f.Observed {
			gaps = append(gaps, model.EvidenceRequirement{
				Type:        "precond:" + p,
				Description: "Precondition not observed: " + p,
			})
			continue
		}
		if hasRequirementTime && !f.At.IsZero() && f.At.After(requirementAt) {
			gaps = append(gaps, model.EvidenceRequirement{
				Type:        "precond_order:" + p,
				Description: "Precondition observed after dependent activity: " + p,
			})
		}
	}
	return gaps
}

func earliestRequirementTime(events []model.Event, index map[string][]int, rule Rule) (time.Time, bool) {
	var out time.Time
	found := false
	for _, req := range rule.Requirements {
		t, ok := earliestEventTime(events, index[req.Type])
		if !ok {
			// Require complete requirement visibility before enforcing
			// temporal precondition ordering.
			return time.Time{}, false
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

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

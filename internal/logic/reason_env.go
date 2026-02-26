package logic

import (
	"fmt"
	"math"
	"strings"
	"time"

	"aman/internal/env"
	"aman/internal/model"
	"aman/internal/ops"
)

// ReasonWithEnv performs feasibility reasoning with environment-aware gates.
// If the environment is empty, behavior falls back to ReasonWithMetrics.
func ReasonWithEnv(events []model.Event, rules []Rule, environment env.Environment) model.ReasoningReport {
	return ReasonWithEnvWithConfig(events, rules, environment, DefaultReasonerConfig())
}

func ReasonWithEnvWithConfig(events []model.Event, rules []Rule, environment env.Environment, cfg ReasonerConfig) model.ReasoningReport {
	return ReasonWithEnvAndMetricsWithConfig(events, rules, environment, nil, false, cfg)
}

// ReasonWithEnvAndMetrics extends ReasonWithMetrics with trust-boundary
// reachability and identity privilege checks.
func ReasonWithEnvAndMetrics(
	events []model.Event,
	rules []Rule,
	environment env.Environment,
	metrics *ops.Metrics,
	includeEvidence bool,
) model.ReasoningReport {
	return ReasonWithEnvAndMetricsWithConfig(events, rules, environment, metrics, includeEvidence, DefaultReasonerConfig())
}

func ReasonWithEnvAndMetricsWithConfig(
	events []model.Event,
	rules []Rule,
	environment env.Environment,
	metrics *ops.Metrics,
	includeEvidence bool,
	cfg ReasonerConfig,
) model.ReasoningReport {
	cfg = sanitizeReasonerConfig(cfg)
	now := cfg.Now()
	if isEnvEmpty(environment) {
		return ReasonWithMetrics(events, rules, metrics, includeEvidence)
	}

	index := make(map[string][]int, 64)
	for i, e := range events {
		index[e.Type] = append(index[e.Type], i)
	}
	facts := deriveCausalFacts(events, index)
	activeFacts := activeFactsFromCausal(facts)

	hostZone := buildHostZoneMap(environment)
	identityPriv := buildIdentityPrivMap(environment)
	graph := env.BuildGraph(environment, activeFacts)
	startZones := attackerStartZones(events, hostZone, index)
	reachableZones := graph.ReachableFrom(startZones)

	results := make([]model.RuleResult, 0, len(rules))
	narrative := []string{}
	for _, rule := range rules {
		if metrics != nil {
			metrics.IncRules(1)
		}
		missing := []model.EvidenceRequirement{}
		supporting := []model.Event{}
		supportingIDs := []string{}
		for _, req := range rule.Requirements {
			if len(index[req.Type]) == 0 {
				missing = append(missing, req)
			} else {
				if includeEvidence {
					for _, idx := range index[req.Type] {
						supporting = append(supporting, events[idx])
					}
				}
				for _, idx := range index[req.Type] {
					if events[idx].ID != "" {
						supportingIDs = append(supportingIDs, events[idx].ID)
					}
				}
			}
		}

		precondOK := true
		requirementAt, hasReqTime := earliestRequirementTime(events, index, rule)
		missingPreconds := preconditionGaps(rule, facts, requirementAt, hasReqTime)
		if len(missingPreconds) > 0 {
			precondOK = false
		}
		missing = append(missing, missingPreconds...)

		contradiction := hasContradiction(rule, index)
		contextReq := contextForRule(rule)
		missingContext := contextReq != "" && !hasContext(events, index, contextReq)
		if contradiction || missingContext {
			precondOK = false
		}
		if missingContext {
			missing = append(missing, model.EvidenceRequirement{
				Type:        "environment_context",
				Description: "Required context not present for rule evaluation",
			})
		}

		envUnreachable := false
		envUnknown := false
		if precondOK && !contradiction && !missingContext {
			envUnreachable, envUnknown = checkEnvUnreachable(rule, events, index, hostZone, reachableZones)
			if envUnreachable || envUnknown {
				precondOK = false
			}
		}

		insufficientPriv := false
		unknownPriv := false
		if precondOK && !contradiction && !missingContext {
			insufficientPriv, unknownPriv = checkInsufficientPriv(rule, events, identityPriv)
			if insufficientPriv || unknownPriv {
				precondOK = false
			}
		}

		causalFeasible, causalBlockers, necessaryCauses, necessaryCauseSets, causalErr := evaluateRuleCausally(
			rule,
			reqPresence(index, rule),
			precondStatusMap(rule, missing),
			map[string]bool{
				"no_contradiction": !contradiction,
				"context_ok":       !missingContext,
				"env_reachable":    !envUnreachable && !envUnknown,
				"identity_priv_ok": !insufficientPriv && !unknownPriv,
			},
			cfg.CausalMaxSetSize,
		)
		feasible := causalFeasible
		causalErrMsg := ""
		if causalErr != nil {
			feasible = false
			causalErrMsg = causalErr.Error()
			missing = append(missing, model.EvidenceRequirement{
				Type:        "causal_model_error",
				Description: "Causal model evaluation failed",
			})
		}
		confidence := scoreConfidence(rule, supporting, missing, precondOK, now)
		if feasible && rule.Constraints.MinConfidence > 0 && confidence < rule.Constraints.MinConfidence {
			feasible = false
			missing = append(missing, model.EvidenceRequirement{
				Type:        "confidence_threshold",
				Description: fmt.Sprintf("Confidence %.2f below rule minimum %.2f", confidence, rule.Constraints.MinConfidence),
			})
		}

		name := rule.Name
		reason := rule.Explain
		gapNarrative := ""
		reasonCode := envReasonCode(precondOK, missing, len(events), contradiction, missingContext, envUnreachable, envUnknown, insufficientPriv, unknownPriv)
		if !precondOK {
			name += " (preconditions unmet)"
		}
		switch {
		case contradiction:
			missing = nil
			reason += " Contradictory evidence observed."
			gapNarrative = "Conflicted: evidence contradicts a required condition for this attack path."
		case missingContext:
			reason += " Required context missing."
			gapNarrative = "Required context is missing to evaluate this rule; treat as incomplete until context is provided."
		case envUnreachable:
			reason += " Target zone is not reachable from current foothold."
			gapNarrative = "Target host zone is unreachable across current trust boundaries."
		case envUnknown:
			reason += " Target host/zone context required for reachability is missing."
			gapNarrative = "Cannot evaluate reachability because target host context is missing."
		case insufficientPriv:
			reason += " Acting identity privilege is insufficient for this technique."
			gapNarrative = "Known identities involved do not have required privilege level."
		case unknownPriv:
			reason += " Identity privilege is unknown in environment inventory."
			gapNarrative = "Cannot prove required identity privilege due to missing inventory context."
		case len(missing) > 0:
			names := requirementNames(missing)
			reason += " Missing evidence: " + strings.Join(names, ", ")
			gapNarrative = "This attack would require " + strings.Join(names, ", ") + " but no such evidence was observed."
		case !precondOK:
			gapNarrative = "Preconditions are not satisfied in the current environment state."
		}

		narrative = append(narrative, narrativeLine(rule, feasible, precondOK, missing))
		results = append(results, model.RuleResult{
			RuleID:             rule.ID,
			Name:               name,
			Feasible:           feasible,
			Conflicted:         contradiction,
			PrecondOK:          precondOK,
			Confidence:         confidence,
			MissingEvidence:    missing,
			SupportingEvents:   supporting,
			SupportingEventIDs: supportingIDs,
			Explanation:        reason,
			GapNarrative:       gapNarrative,
			ReasonCode:         reasonCode,
			CausalBlockers:     causalBlockers,
			CausalError:        causalErrMsg,
			NecessaryCauses:    necessaryCauses,
			NecessaryCauseSets: necessaryCauseSets,
		})
	}

	return model.ReasoningReport{
		GeneratedAt:     now,
		Summary:         "Env-aware feasibility reasoning over evidence, trust graph, and identity privileges.",
		Results:         results,
		Narrative:       narrative,
		ConfidenceModel: "evidence_weighted",
		ConfidenceNote:  "Rule-based confidence weighted by evidence coverage and recency; not calibrated.",
	}
}

func isEnvEmpty(environment env.Environment) bool {
	return len(environment.Hosts) == 0 && len(environment.Identities) == 0 && len(environment.TrustBoundaries) == 0
}

func checkEnvUnreachable(
	rule Rule,
	events []model.Event,
	index map[string][]int,
	hostZone map[string]string,
	reachableZones map[string]bool,
) (unreachable bool, unknown bool) {
	if !requiresReachability(rule) {
		return false, false
	}
	targetHost := extractTargetHost(rule, index, events)
	if targetHost == "" {
		if rule.RequiresReachability != nil && *rule.RequiresReachability {
			return false, true
		}
		return false, false
	}
	zone, known := hostZone[targetHost]
	if !known || zone == "" {
		if rule.RequiresReachability != nil && *rule.RequiresReachability {
			return false, true
		}
		return false, false
	}
	return !reachableZones["zone:"+zone], false
}

func checkInsufficientPriv(
	rule Rule,
	events []model.Event,
	identityPriv map[string]string,
) (insufficient bool, unknown bool) {
	if !requiresHighPriv(rule) {
		return false, false
	}
	actors := map[string]bool{}
	for _, ev := range events {
		if ev.User != "" {
			actors[ev.User] = true
		}
	}
	if len(actors) == 0 {
		return false, false
	}
	for actor := range actors {
		priv, known := identityPriv[actor]
		if !known {
			return false, true
		}
		if priv == "high" || priv == "admin" {
			return false, false
		}
	}
	return true, false
}

func scoreConfidence(
	rule Rule,
	supporting []model.Event,
	missing []model.EvidenceRequirement,
	precondOK bool,
	now time.Time,
) float64 {
	if !precondOK {
		return confidenceFloor
	}
	total := float64(len(rule.Requirements))
	if total == 0 {
		return confidenceFloor
	}
	present := total - float64(len(missing))
	if present < 0 {
		present = 0
	}
	coverage := present / total
	recency := recencyScore(supporting, now)
	extra := float64(len(supporting)) - present
	if extra < 0 {
		extra = 0
	}
	corroboration := math.Min(extra/5.0, 1.0) * confidenceCorroborW
	raw := coverage*confidenceCoverageW + recency*confidenceRecencyW + corroboration
	return math.Max(confidenceFloor, math.Min(confidenceCeiling, raw))
}

func recencyScore(events []model.Event, now time.Time) float64 {
	if len(events) == 0 {
		return 0
	}
	var newest time.Time
	for _, ev := range events {
		if ev.Time.After(newest) {
			newest = ev.Time
		}
	}
	if newest.IsZero() {
		return confidenceNoTSRecency
	}
	age := now.Sub(newest)
	if age < 0 {
		age = 0
	}
	if age >= confidenceRecencySpan {
		return 0
	}
	return 1.0 - float64(age)/float64(confidenceRecencySpan)
}

func envReasonCode(
	precondOK bool,
	missing []model.EvidenceRequirement,
	eventCount int,
	contradiction bool,
	missingContext bool,
	envUnreachable bool,
	envUnknown bool,
	insufficientPriv bool,
	unknownPriv bool,
) string {
	switch {
	case contradiction:
		return "conflicted"
	case missingContext:
		return "environment_unknown"
	case envUnreachable:
		return "env_unreachable"
	case envUnknown:
		return "environment_unknown"
	case insufficientPriv:
		return "identity_insufficient_priv"
	case unknownPriv:
		return "environment_unknown"
	case !precondOK:
		if len(missing) > 0 {
			return "evidence_gap"
		}
		return "precond_missing"
	case len(missing) > 0 && eventCount == 0:
		return "environment_unknown"
	case len(missing) > 0:
		return "evidence_gap"
	default:
		return ""
	}
}

func buildHostZoneMap(environment env.Environment) map[string]string {
	m := make(map[string]string, len(environment.Hosts))
	for _, h := range environment.Hosts {
		m[h.ID] = h.Zone
	}
	return m
}

func buildIdentityPrivMap(environment env.Environment) map[string]string {
	m := make(map[string]string, len(environment.Identities))
	for _, id := range environment.Identities {
		m[id.ID] = id.PrivLevel
	}
	return m
}

// Uses strong compromise/foothold indicators only. Avoids treating every
// event host as attacker-controlled.
func attackerStartZones(events []model.Event, hostZone map[string]string, index map[string][]int) []string {
	footholdTypes := []string{
		"beacon_outbound",
		"lsass_access",
		"process_creation",
		"token_manipulation",
		"admin_group_change",
	}
	seen := map[string]bool{}
	out := []string{}
	for _, typ := range footholdTypes {
		for _, idx := range index[typ] {
			host := events[idx].Host
			zone := hostZone[host]
			if host != "" && zone != "" && !seen[zone] {
				seen[zone] = true
				out = append(out, "zone:"+zone)
			}
		}
	}
	return out
}

func extractTargetHost(rule Rule, index map[string][]int, allEvents []model.Event) string {
	types := targetEventTypesForRule(rule)
	if len(types) == 0 {
		return ""
	}
	for _, t := range types {
		for _, idx := range index[t] {
			ev := allEvents[idx]
			if ev.Host != "" {
				return ev.Host
			}
		}
	}
	for _, ev := range allEvents {
		if ev.Host != "" {
			return ev.Host
		}
	}
	return ""
}

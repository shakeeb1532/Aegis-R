package overlay

import (
	"fmt"
	"sort"
	"strings"

	"aman/internal/logic"
	"aman/internal/model"
)

var defaultSourceThreshold = map[string]float64{
	"identity": 0.12,
	"cloud":    0.18,
	"edr":      0.24,
	"mixed":    0.20,
}

var defaultSourceBoost = map[string]float64{
	"identity": 0.16,
	"cloud":    0.10,
	"edr":      0.06,
	"mixed":    0.08,
}

func BuildHighRecallAlerts(events []model.Event, rules []logic.Rule, threshold float64, maxAlerts int) []model.AIAlert {
	if threshold < 0 {
		threshold = 0
	}
	if maxAlerts <= 0 {
		maxAlerts = len(rules)
	}
	present := map[string]bool{}
	typeClass := map[string]string{}
	for _, ev := range events {
		if ev.Type != "" {
			present[ev.Type] = true
			typeClass[ev.Type] = classifySource(ev)
		}
	}

	alerts := make([]model.AIAlert, 0, len(rules))
	for _, rule := range rules {
		if len(rule.Requirements) == 0 {
			continue
		}
		hits := 0
		for _, req := range rule.Requirements {
			if present[req.Type] {
				hits++
			}
		}
		// Require at least one observed evidence type before emitting a candidate.
		if hits == 0 {
			continue
		}
		coverage := float64(hits) / float64(len(rule.Requirements))
		profile := dominantProfile(rule, present, typeClass)
		// Bias toward recall: any evidence hit starts above neutral.
		score := 0.35 + (0.65 * coverage) + defaultSourceBoost[profile]
		minThreshold := threshold
		if t, ok := defaultSourceThreshold[profile]; ok && t < minThreshold {
			minThreshold = t
		}
		if score < minThreshold {
			continue
		}
		alerts = append(alerts, model.AIAlert{
			RuleID:       rule.ID,
			Name:         rule.Name,
			Sensitivity:  clamp(score, 0, 1),
			EvidenceHits: hits,
			Status:       "candidate",
			Reason:       fmt.Sprintf("matched %d/%d rule evidence types (%s profile)", hits, len(rule.Requirements), profile),
		})
	}

	sort.Slice(alerts, func(i, j int) bool {
		if alerts[i].Sensitivity == alerts[j].Sensitivity {
			return alerts[i].RuleID < alerts[j].RuleID
		}
		return alerts[i].Sensitivity > alerts[j].Sensitivity
	})
	if len(alerts) > maxAlerts {
		alerts = alerts[:maxAlerts]
	}
	return alerts
}

func ApplyCausalFilter(alerts []model.AIAlert, results []model.RuleResult) ([]model.AIAlert, model.AIOverlaySummary) {
	byRule := map[string]model.RuleResult{}
	for _, r := range results {
		byRule[r.RuleID] = r
	}
	summary := model.AIOverlaySummary{
		Enabled:        true,
		Mode:           "high-recall-overlay",
		CandidateCount: len(alerts),
		Notes: []string{
			"ai_layer_is_high_recall",
			"aman_causal_validation_controls_escalation",
		},
	}

	filtered := make([]model.AIAlert, len(alerts))
	for i, alert := range alerts {
		next := alert
		r, ok := byRule[alert.RuleID]
		if !ok {
			next.Status = "triaged"
			next.Reason = "no deterministic result available yet"
			summary.TriagedCount++
			filtered[i] = next
			continue
		}
		switch {
		case r.Feasible:
			next.Status = "escalated"
			next.Reason = "causal preconditions and evidence are feasible"
			summary.EscalatedCount++
		case r.PolicyImpossible || (!r.PrecondOK && len(r.MissingEvidence) == 0):
			next.Status = "suppressed"
			next.Reason = "causal validation rejected this path"
			summary.SuppressedCount++
		default:
			next.Status = "triaged"
			next.Reason = "potential path requires more evidence"
			summary.TriagedCount++
		}
		filtered[i] = next
	}
	return filtered, summary
}

func clamp(v, min, max float64) float64 {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

func classifySource(ev model.Event) string {
	if ev.Details != nil {
		if srcRaw, ok := ev.Details["source"]; ok {
			if src, ok := srcRaw.(string); ok {
				class := classifySourceString(src)
				if class != "mixed" {
					return class
				}
			}
		}
	}
	return classifySourceString(ev.Type)
}

func classifySourceString(in string) string {
	s := strings.ToLower(strings.TrimSpace(in))
	switch {
	case containsAny(s, []string{"okta", "entra", "azuread", "aad", "identity", "auth", "login", "mfa", "token", "iam"}):
		return "identity"
	case containsAny(s, []string{"cloudtrail", "aws", "gcp", "azure", "k8s", "kubernetes", "security_group", "vpc", "s3", "bucket", "cloud"}):
		return "cloud"
	case containsAny(s, []string{"edr", "defender", "crowdstrike", "sentinelone", "carbonblack", "xdr", "process", "lsass", "registry", "powershell"}):
		return "edr"
	default:
		return "mixed"
	}
}

func dominantProfile(rule logic.Rule, present map[string]bool, typeClass map[string]string) string {
	counts := map[string]int{
		"identity": 0,
		"cloud":    0,
		"edr":      0,
		"mixed":    0,
	}
	for _, req := range rule.Requirements {
		if !present[req.Type] {
			continue
		}
		class := typeClass[req.Type]
		if class == "" {
			class = "mixed"
		}
		counts[class]++
	}
	best := "mixed"
	bestCount := -1
	order := []string{"identity", "cloud", "edr", "mixed"}
	for _, k := range order {
		if counts[k] > bestCount {
			best = k
			bestCount = counts[k]
		}
	}
	return best
}

func containsAny(s string, parts []string) bool {
	for _, p := range parts {
		if strings.Contains(s, p) {
			return true
		}
	}
	return false
}

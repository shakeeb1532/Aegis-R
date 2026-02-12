package report

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
	"time"

	"aman/internal/model"
)

func RenderCLI(rep model.ReasoningReport) string {
	buf := &bytes.Buffer{}
	now := time.Now().UTC().Format(time.RFC3339)
	fmt.Fprintf(buf, "Aman Reasoning Report (%s)\n", now)
	fmt.Fprintf(buf, "%s\n\n", rep.Summary)
	if rep.ConfidenceModel != "" {
		fmt.Fprintf(buf, "Confidence model: %s\n", rep.ConfidenceModel)
		if rep.ConfidenceNote != "" {
			fmt.Fprintf(buf, "Confidence note: %s\n", rep.ConfidenceNote)
		}
		fmt.Fprintln(buf, "")
	}

	sort.Slice(rep.Results, func(i, j int) bool {
		if rep.Results[i].Feasible == rep.Results[j].Feasible {
			return rep.Results[i].Confidence > rep.Results[j].Confidence
		}
		return rep.Results[i].Feasible
	})

	for _, r := range rep.Results {
		status := "NOT FEASIBLE"
		if r.Feasible {
			status = "FEASIBLE"
		}
		fmt.Fprintf(buf, "- [%s] %s (%s, %.2f)\n", status, r.Name, r.RuleID, r.Confidence)
		if r.DecisionLabel != "" || r.ReasonCode != "" || r.ThreadID != "" {
			fmt.Fprintf(buf, "  Decision: %s\n", r.DecisionLabel)
			if r.ReasonCode != "" {
				fmt.Fprintf(buf, "  Reason code: %s\n", r.ReasonCode)
			}
			if r.ThreadID != "" {
				fmt.Fprintf(buf, "  Thread: %s\n", r.ThreadID)
			}
			if r.ThreadConfidence > 0 || r.ThreadReason != "" {
				fmt.Fprintf(buf, "  Thread confidence: %.2f (%s)\n", r.ThreadConfidence, r.ThreadReason)
			}
			if r.CacheHit {
				fmt.Fprintf(buf, "  Cache: HIT\n")
			}
		}
		if r.LikelihoodScore > 0 {
			source := r.LikelihoodSource
			if source == "" {
				source = "assist"
			}
			fmt.Fprintf(buf, "  Likelihood: %.2f (%s)\n", r.LikelihoodScore, source)
		}
		fmt.Fprintf(buf, "  %s\n", r.Explanation)
		if r.GapNarrative != "" {
			fmt.Fprintf(buf, "  Gap: %s\n", r.GapNarrative)
		}
		if len(r.SupportingEventIDs) > 0 {
			fmt.Fprintf(buf, "  Evidence IDs: %s\n", strings.Join(r.SupportingEventIDs, ", "))
		}
		if len(r.MissingEvidence) > 0 {
			fmt.Fprintf(buf, "  Missing Evidence:\n")
			for _, m := range r.MissingEvidence {
				fmt.Fprintf(buf, "  - %s: %s\n", m.Type, m.Description)
			}
		}
		fmt.Fprintln(buf, "")
	}
	if len(rep.Narrative) > 0 {
		fmt.Fprintln(buf, "Reasoning Narrative:")
		for _, n := range rep.Narrative {
			fmt.Fprintf(buf, "- %s\n", n)
		}
	}
	if rep.Explanation != "" {
		fmt.Fprintln(buf, "")
		label := "Explanation"
		if rep.ExplanationSource != "" {
			label = fmt.Sprintf("Explanation (%s)", rep.ExplanationSource)
		}
		fmt.Fprintf(buf, "%s:\n", label)
		fmt.Fprintf(buf, "%s\n", rep.Explanation)
		if len(rep.SuggestedSteps) > 0 {
			fmt.Fprintln(buf, "")
			fmt.Fprintln(buf, "Suggested steps:")
			for _, step := range rep.SuggestedSteps {
				fmt.Fprintf(buf, "- %s\n", step)
			}
		}
	}
	if len(rep.RecommendedTelemetry) > 0 {
		fmt.Fprintln(buf, "")
		label := "Recommended telemetry"
		if rep.TelemetrySource != "" {
			label = fmt.Sprintf("Recommended telemetry (%s)", rep.TelemetrySource)
		}
		fmt.Fprintf(buf, "%s:\n", label)
		for _, item := range rep.RecommendedTelemetry {
			fmt.Fprintf(buf, "- %s\n", item)
		}
	}
	if len(rep.SimilarIncidents) > 0 {
		fmt.Fprintln(buf, "")
		fmt.Fprintln(buf, "Similar incidents (advisory):")
		for _, inc := range rep.SimilarIncidents {
			fmt.Fprintf(buf, "- %s (score %.2f): %s\n", inc.ID, inc.Score, inc.Summary)
		}
	}
	if len(rep.SuggestedPlaybooks) > 0 {
		fmt.Fprintln(buf, "")
		fmt.Fprintln(buf, "Suggested playbooks (advisory):")
		for _, pb := range rep.SuggestedPlaybooks {
			fmt.Fprintf(buf, "- %s\n", pb)
		}
	}
	return buf.String()
}

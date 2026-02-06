package report

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
	"time"

	"aegisr/internal/model"
)

func RenderCLI(rep model.ReasoningReport) string {
	buf := &bytes.Buffer{}
	now := time.Now().UTC().Format(time.RFC3339)
	fmt.Fprintf(buf, "Aegis-R Reasoning Report (%s)\n", now)
	fmt.Fprintf(buf, "%s\n\n", rep.Summary)

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
	return buf.String()
}

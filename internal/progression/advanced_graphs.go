package progression

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"aman/internal/env"
	"aman/internal/state"
)

type StageEdge struct {
	From          string
	To            string
	Count         int
	AvgConfidence float64
}

type BlastRadius struct {
	CompromisedCritical []string
	ReachableCritical   []string
	ReachableTotal      int
}

type ControlPoint struct {
	ID     string
	Layer  string
	Target string
	Action string
	Reason string
}

type IdentityPivot struct {
	Kind          string
	From          string
	To            string
	Via           string
	Count         int
	AvgConfidence float64
}

type TimeSlice struct {
	Start            time.Time
	End              time.Time
	EventCount       int
	UniqueAssets     int
	UniquePrincipals int
	StageCounts      map[string]int
}

type ConfidenceEdge struct {
	From          string
	To            string
	Count         int
	AvgConfidence float64
	LowConfidence bool
}

func BuildKillChainEdges(events []state.ProgressEvent) []StageEdge {
	if len(events) < 2 {
		return []StageEdge{}
	}
	ordered := append([]state.ProgressEvent(nil), events...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Time.Before(ordered[j].Time) })
	type agg struct {
		count int
		sum   float64
	}
	edges := map[string]*agg{}
	for i := 1; i < len(ordered); i++ {
		from := strings.TrimSpace(ordered[i-1].Stage)
		to := strings.TrimSpace(ordered[i].Stage)
		if from == "" || to == "" || from == to {
			continue
		}
		key := from + "->" + to
		if edges[key] == nil {
			edges[key] = &agg{}
		}
		edges[key].count++
		edges[key].sum += (ordered[i-1].Confidence + ordered[i].Confidence) / 2
	}
	out := []StageEdge{}
	for key, v := range edges {
		parts := strings.SplitN(key, "->", 2)
		out = append(out, StageEdge{
			From:          parts[0],
			To:            parts[1],
			Count:         v.count,
			AvgConfidence: v.sum / float64(v.count),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].From+out[i].To < out[j].From+out[j].To
		}
		return out[i].Count > out[j].Count
	})
	return out
}

func RenderKillChainMermaid(edges []StageEdge) string {
	if len(edges) == 0 {
		return "flowchart LR\n  A[\"No kill-chain transitions\"]\n"
	}
	var b strings.Builder
	b.WriteString("flowchart LR\n")
	for i, e := range edges {
		from := fmt.Sprintf("K%dA", i+1)
		to := fmt.Sprintf("K%dB", i+1)
		b.WriteString(fmt.Sprintf("  %s[\"%s\"]\n", from, e.From))
		b.WriteString(fmt.Sprintf("  %s[\"%s\"]\n", to, e.To))
		b.WriteString(fmt.Sprintf("  %s -->|\"n=%d conf=%.2f\"| %s\n", from, e.Count, e.AvgConfidence, to))
	}
	return b.String()
}

func BuildBlastRadius(environment env.Environment, st state.AttackState) BlastRadius {
	critical := map[string]bool{}
	for _, h := range environment.Hosts {
		if h.Critical {
			critical[h.ID] = true
		}
	}
	comp := []string{}
	reach := []string{}
	for host := range st.CompromisedHosts {
		if critical[host] {
			comp = append(comp, host)
		}
	}
	for host := range st.ReachableHosts {
		if critical[host] {
			reach = append(reach, host)
		}
	}
	sort.Strings(comp)
	sort.Strings(reach)
	return BlastRadius{
		CompromisedCritical: comp,
		ReachableCritical:   reach,
		ReachableTotal:      len(st.ReachableHosts),
	}
}

func SuggestControlPoints(environment env.Environment, st state.AttackState) []ControlPoint {
	seen := map[string]bool{}
	out := []ControlPoint{}
	add := func(cp ControlPoint) {
		if seen[cp.ID] {
			return
		}
		seen[cp.ID] = true
		out = append(out, cp)
	}

	stages := map[string]bool{}
	for _, p := range st.Progression {
		stages[p.Stage] = true
	}
	if stages["identity_auth"] {
		add(ControlPoint{
			ID:     "identity-mfa",
			Layer:  "identity",
			Target: "idp",
			Action: "enforce conditional MFA and risky-login policy",
			Reason: "identity_auth stage observed",
		})
	}
	if stages["host_execution"] {
		add(ControlPoint{
			ID:     "endpoint-exec",
			Layer:  "endpoint",
			Target: "edr",
			Action: "restrict LOLBins/script interpreters and isolate suspicious hosts",
			Reason: "host_execution stage observed",
		})
	}
	if stages["lateral_network"] {
		add(ControlPoint{
			ID:     "network-seg",
			Layer:  "network",
			Target: "segmentation",
			Action: "tighten east-west ACLs for compromised/reachable zones",
			Reason: "lateral_network stage observed",
		})
	}
	if stages["data_impact"] {
		add(ControlPoint{
			ID:     "egress-dlp",
			Layer:  "data",
			Target: "egress",
			Action: "block unsanctioned bulk transfer channels and enforce DLP",
			Reason: "data_impact stage observed",
		})
	}
	for _, tb := range environment.TrustBoundaries {
		if tb.Mode == "allow" {
			continue
		}
		add(ControlPoint{
			ID:     "tb-" + tb.ID,
			Layer:  "network",
			Target: tb.From + "->" + tb.To,
			Action: "review boundary mode and exceptions",
			Reason: "boundary mode is " + tb.Mode,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func BuildIdentityPivots(events []state.ProgressEvent) []IdentityPivot {
	if len(events) == 0 {
		return []IdentityPivot{}
	}
	ordered := append([]state.ProgressEvent(nil), events...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Time.Before(ordered[j].Time) })
	type agg struct {
		count int
		sum   float64
		kind  string
		from  string
		to    string
		via   string
	}
	piv := map[string]*agg{}
	for i := 0; i < len(ordered); i++ {
		e := ordered[i]
		if e.Principal != "" && e.Asset != "" {
			k := "pa|" + e.Principal + "|" + e.Asset
			if piv[k] == nil {
				piv[k] = &agg{kind: "principal_asset", from: e.Principal, to: e.Asset, via: e.Action}
			}
			piv[k].count++
			piv[k].sum += e.Confidence
		}
		if i > 0 {
			prev := ordered[i-1]
			if prev.Asset == "" || prev.Asset != e.Asset {
				continue
			}
			if prev.Principal == "" || e.Principal == "" || prev.Principal == e.Principal {
				continue
			}
			if e.Time.Sub(prev.Time) > 30*time.Minute {
				continue
			}
			k := "pp|" + prev.Principal + "|" + e.Principal + "|" + e.Asset
			if piv[k] == nil {
				piv[k] = &agg{kind: "principal_principal", from: prev.Principal, to: e.Principal, via: e.Asset}
			}
			piv[k].count++
			piv[k].sum += (prev.Confidence + e.Confidence) / 2
		}
	}
	out := []IdentityPivot{}
	for _, p := range piv {
		out = append(out, IdentityPivot{
			Kind:          p.kind,
			From:          p.from,
			To:            p.to,
			Via:           p.via,
			Count:         p.count,
			AvgConfidence: p.sum / float64(p.count),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].From+out[i].To < out[j].From+out[j].To
		}
		return out[i].Count > out[j].Count
	})
	return out
}

func RenderIdentityPivotMermaid(pivots []IdentityPivot) string {
	if len(pivots) == 0 {
		return "flowchart LR\n  A[\"No identity pivots\"]\n"
	}
	var b strings.Builder
	b.WriteString("flowchart LR\n")
	for i, p := range pivots {
		a := fmt.Sprintf("I%dA", i+1)
		c := fmt.Sprintf("I%dB", i+1)
		b.WriteString(fmt.Sprintf("  %s[\"%s\"]\n", a, p.From))
		b.WriteString(fmt.Sprintf("  %s[\"%s\"]\n", c, p.To))
		b.WriteString(fmt.Sprintf("  %s -->|\"%s n=%d conf=%.2f\"| %s\n", a, p.Kind, p.Count, p.AvgConfidence, c))
	}
	return b.String()
}

func BuildTimeLapse(events []state.ProgressEvent, step time.Duration) []TimeSlice {
	if len(events) == 0 {
		return []TimeSlice{}
	}
	if step <= 0 {
		step = 5 * time.Minute
	}
	ordered := append([]state.ProgressEvent(nil), events...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Time.Before(ordered[j].Time) })
	base := ordered[0].Time
	type bucket struct {
		start      time.Time
		end        time.Time
		count      int
		assets     map[string]bool
		principals map[string]bool
		stages     map[string]int
	}
	buckets := map[int64]*bucket{}
	for _, e := range ordered {
		idx := int64(e.Time.Sub(base) / step)
		if buckets[idx] == nil {
			start := base.Add(time.Duration(idx) * step)
			buckets[idx] = &bucket{
				start:      start,
				end:        start.Add(step),
				assets:     map[string]bool{},
				principals: map[string]bool{},
				stages:     map[string]int{},
			}
		}
		b := buckets[idx]
		b.count++
		if e.Asset != "" {
			b.assets[e.Asset] = true
		}
		if e.Principal != "" {
			b.principals[e.Principal] = true
		}
		if e.Stage != "" {
			b.stages[e.Stage]++
		}
	}
	keys := []int64{}
	for k := range buckets {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	out := make([]TimeSlice, 0, len(keys))
	for _, k := range keys {
		b := buckets[k]
		out = append(out, TimeSlice{
			Start:            b.start,
			End:              b.end,
			EventCount:       b.count,
			UniqueAssets:     len(b.assets),
			UniquePrincipals: len(b.principals),
			StageCounts:      b.stages,
		})
	}
	return out
}

func BuildEvidenceConfidenceEdges(events []state.ProgressEvent) []ConfidenceEdge {
	kill := BuildKillChainEdges(events)
	out := make([]ConfidenceEdge, 0, len(kill))
	for _, e := range kill {
		out = append(out, ConfidenceEdge{
			From:          e.From,
			To:            e.To,
			Count:         e.Count,
			AvgConfidence: e.AvgConfidence,
			LowConfidence: e.AvgConfidence < 0.60,
		})
	}
	return out
}

func RenderConfidenceMermaid(edges []ConfidenceEdge) string {
	if len(edges) == 0 {
		return "flowchart LR\n  A[\"No confidence edges\"]\n"
	}
	var b strings.Builder
	b.WriteString("flowchart LR\n")
	for i, e := range edges {
		a := fmt.Sprintf("C%dA", i+1)
		c := fmt.Sprintf("C%dB", i+1)
		b.WriteString(fmt.Sprintf("  %s[\"%s\"]\n", a, e.From))
		b.WriteString(fmt.Sprintf("  %s[\"%s\"]\n", c, e.To))
		tag := "high"
		if e.LowConfidence {
			tag = "low"
		}
		b.WriteString(fmt.Sprintf("  %s -->|\"%s conf=%.2f n=%d\"| %s\n", a, tag, e.AvgConfidence, e.Count, c))
	}
	return b.String()
}

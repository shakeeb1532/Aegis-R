package progression

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"aman/internal/state"
)

type AttackPath struct {
	ID         string
	Asset      string
	Principal  string
	Stages     []string
	Actions    []string
	FirstSeen  time.Time
	LastSeen   time.Time
	Confidence float64
}

func BuildAttackPaths(events []state.ProgressEvent) []AttackPath {
	type agg struct {
		asset      string
		principal  string
		stageSet   map[string]bool
		actionSet  map[string]bool
		firstSeen  time.Time
		lastSeen   time.Time
		confidence float64
	}
	byKey := map[string]*agg{}
	for _, e := range events {
		asset := e.Asset
		if asset == "" {
			asset = "unknown"
		}
		principal := e.Principal
		if principal == "" {
			principal = "unknown"
		}
		key := asset + "|" + principal
		a, ok := byKey[key]
		if !ok {
			a = &agg{
				asset:      asset,
				principal:  principal,
				stageSet:   map[string]bool{},
				actionSet:  map[string]bool{},
				firstSeen:  e.Time,
				lastSeen:   e.Time,
				confidence: e.Confidence,
			}
			byKey[key] = a
		}
		if e.Time.Before(a.firstSeen) {
			a.firstSeen = e.Time
		}
		if e.Time.After(a.lastSeen) {
			a.lastSeen = e.Time
		}
		if e.Confidence > a.confidence {
			a.confidence = e.Confidence
		}
		if e.Stage != "" {
			a.stageSet[e.Stage] = true
		}
		if e.Action != "" {
			a.actionSet[e.Action] = true
		}
	}
	paths := make([]AttackPath, 0, len(byKey))
	for _, a := range byKey {
		stages := sortedKeys(a.stageSet)
		actions := sortedKeys(a.actionSet)
		paths = append(paths, AttackPath{
			ID:         fmt.Sprintf("path:%s:%s", a.asset, a.principal),
			Asset:      a.asset,
			Principal:  a.principal,
			Stages:     stages,
			Actions:    actions,
			FirstSeen:  a.firstSeen,
			LastSeen:   a.lastSeen,
			Confidence: a.confidence,
		})
	}
	sort.Slice(paths, func(i, j int) bool {
		if paths[i].Confidence == paths[j].Confidence {
			return paths[i].ID < paths[j].ID
		}
		return paths[i].Confidence > paths[j].Confidence
	})
	return paths
}

func RenderMermaid(paths []AttackPath) string {
	if len(paths) == 0 {
		return "flowchart LR\n  A[\"No progression paths\"]\n"
	}
	var b strings.Builder
	b.WriteString("flowchart LR\n")
	for i, path := range paths {
		base := fmt.Sprintf("P%d", i+1)
		label := fmt.Sprintf("%s\\n%s", path.Asset, path.Principal)
		b.WriteString(fmt.Sprintf("  %s[\"%s\"]\n", base, label))
		prev := base
		for j, stage := range path.Stages {
			node := fmt.Sprintf("%sS%d", base, j+1)
			b.WriteString(fmt.Sprintf("  %s[\"%s\"]\n", node, stage))
			b.WriteString(fmt.Sprintf("  %s --> %s\n", prev, node))
			prev = node
		}
	}
	return b.String()
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

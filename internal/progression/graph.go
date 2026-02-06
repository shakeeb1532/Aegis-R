package progression

import (
	"aegisr/internal/env"
	"aegisr/internal/state"
)

func OverlayGraph(environment env.Environment, st *state.AttackState) {
	g := env.BuildGraph(environment)
	current := []string{}
	for _, host := range st.Position.Assets {
		current = append(current, "host:"+host)
	}
	for _, id := range st.Position.Principals {
		current = append(current, "id:"+id)
	}
	reach := g.ReachableFrom(current)
	reachable := []string{}
	for node := range reach {
		reachable = append(reachable, node)
	}
	st.GraphOverlay.CurrentNodes = current
	st.GraphOverlay.Reachable = reachable
}

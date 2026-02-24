package env

import "fmt"

type Graph struct {
	Nodes        map[string]bool
	Edges        map[string][]string
	ReverseEdges map[string][]string
	DenyEdges    map[string]map[string]bool
}

func BuildGraph(e Environment) Graph {
	g := Graph{
		Nodes:        map[string]bool{},
		Edges:        map[string][]string{},
		ReverseEdges: map[string][]string{},
		DenyEdges:    map[string]map[string]bool{},
	}
	for _, h := range e.Hosts {
		g.Nodes[fmt.Sprintf("host:%s", h.ID)] = true
	}
	for _, id := range e.Identities {
		g.Nodes[fmt.Sprintf("id:%s", id.ID)] = true
	}
	for _, tb := range e.TrustBoundaries {
		// connect zone -> zone via trust boundary
		from := fmt.Sprintf("zone:%s", tb.From)
		to := fmt.Sprintf("zone:%s", tb.To)
		g.Nodes[from] = true
		g.Nodes[to] = true
		if tb.Mode == "deny" {
			if g.DenyEdges[from] == nil {
				g.DenyEdges[from] = map[string]bool{}
			}
			g.DenyEdges[from][to] = true
			continue
		}
		if tb.Mode != "allow" {
			continue
		}
		g.Edges[from] = append(g.Edges[from], to)
		g.ReverseEdges[to] = append(g.ReverseEdges[to], from)
	}
	return g
}

func (g Graph) ReachableFrom(start []string) map[string]bool {
	reachable := map[string]bool{}
	queue := []string{}
	origins := map[string]map[string]bool{}
	for _, s := range start {
		reachable[s] = true
		queue = append(queue, s)
		origins[s] = map[string]bool{s: true}
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, nxt := range g.Edges[cur] {
			if g.isDeniedFromAnyOrigin(nxt, origins[cur]) {
				continue
			}
			if origins[nxt] == nil {
				origins[nxt] = map[string]bool{}
			}
			for o := range origins[cur] {
				origins[nxt][o] = true
			}
			if !reachable[nxt] {
				reachable[nxt] = true
				queue = append(queue, nxt)
			}
		}
	}
	return reachable
}

func (g Graph) ReachableTo(target []string) map[string]bool {
	reachable := map[string]bool{}
	queue := []string{}
	for _, t := range target {
		reachable[t] = true
		queue = append(queue, t)
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, nxt := range g.ReverseEdges[cur] {
			if !reachable[nxt] {
				reachable[nxt] = true
				queue = append(queue, nxt)
			}
		}
	}
	return reachable
}

func (g Graph) isDeniedFromAnyOrigin(node string, origins map[string]bool) bool {
	if len(origins) == 0 {
		return false
	}
	for origin := range origins {
		if deniedTargets, ok := g.DenyEdges[origin]; ok && deniedTargets[node] {
			return true
		}
	}
	return false
}

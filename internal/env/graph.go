package env

import "fmt"

type Graph struct {
	Nodes map[string]bool
	Edges map[string][]string
}

func BuildGraph(e Environment) Graph {
	g := Graph{Nodes: map[string]bool{}, Edges: map[string][]string{}}
	for _, h := range e.Hosts {
		g.Nodes[fmt.Sprintf("host:%s", h.ID)] = true
	}
	for _, id := range e.Identities {
		g.Nodes[fmt.Sprintf("id:%s", id.ID)] = true
	}
	for _, tb := range e.TrustBoundaries {
		if tb.Mode != "allow" {
			continue
		}
		// connect zone -> zone via trust boundary
		from := fmt.Sprintf("zone:%s", tb.From)
		to := fmt.Sprintf("zone:%s", tb.To)
		g.Nodes[from] = true
		g.Nodes[to] = true
		g.Edges[from] = append(g.Edges[from], to)
	}
	return g
}

func (g Graph) ReachableFrom(start []string) map[string]bool {
	reachable := map[string]bool{}
	queue := []string{}
	for _, s := range start {
		reachable[s] = true
		queue = append(queue, s)
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, nxt := range g.Edges[cur] {
			if !reachable[nxt] {
				reachable[nxt] = true
				queue = append(queue, nxt)
			}
		}
	}
	return reachable
}

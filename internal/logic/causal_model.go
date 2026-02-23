package logic

import (
	"fmt"
	"sort"

	"aman/internal/causal"
	"aman/internal/model"
)

func evaluateRuleCausally(
	rule Rule,
	reqPresent map[string]bool,
	precondOK map[string]bool,
	gates map[string]bool,
	maxSetSize int,
) (bool, []string, []string, [][]string, error) {
	nodes := []causal.Node{}
	base := causal.Assignment{}

	reqVars := []string{}
	for _, req := range rule.Requirements {
		v := "req:" + req.Type
		reqVars = append(reqVars, v)
		nodes = append(nodes, causal.Node{Name: v, Exogenous: true})
		base[v] = reqPresent[req.Type]
	}
	preVars := []string{}
	for _, p := range rule.Preconds {
		v := "pre:" + p
		preVars = append(preVars, v)
		nodes = append(nodes, causal.Node{Name: v, Exogenous: true})
		base[v] = precondOK[p]
	}

	gateVars := []string{"gate:no_contradiction", "gate:context_ok", "gate:env_reachable", "gate:identity_priv_ok"}
	nodes = append(nodes,
		causal.Node{Name: gateVars[0], Exogenous: true},
		causal.Node{Name: gateVars[1], Exogenous: true},
		causal.Node{Name: gateVars[2], Exogenous: true},
		causal.Node{Name: gateVars[3], Exogenous: true},
	)
	base[gateVars[0]] = gates["no_contradiction"]
	base[gateVars[1]] = gates["context_ok"]
	base[gateVars[2]] = gates["env_reachable"]
	base[gateVars[3]] = gates["identity_priv_ok"]

	parents := []string{}
	parents = append(parents, reqVars...)
	parents = append(parents, preVars...)
	parents = append(parents, gateVars...)
	terms := make([]causal.Expr, 0, len(parents))
	for _, p := range parents {
		terms = append(terms, causal.VarExpr{Name: p})
	}
	nodes = append(nodes, causal.Node{
		Name:     "outcome:feasible",
		Parents:  parents,
		Equation: causal.AndExpr{Terms: terms},
	})

	m, err := causal.NewModel("outcome:feasible", nodes)
	if err != nil {
		return false, []string{"scm_error"}, nil, nil, fmt.Errorf("build causal model for %s: %w", rule.ID, err)
	}
	assignment, err := m.Evaluate(base, nil)
	if err != nil {
		return false, []string{"scm_eval_error"}, nil, nil, fmt.Errorf("evaluate causal model for %s: %w", rule.ID, err)
	}
	feasible, err := m.OutcomeValue(assignment)
	if err != nil {
		return false, []string{"scm_outcome_error"}, nil, nil, fmt.Errorf("compute causal outcome for %s: %w", rule.ID, err)
	}

	blockers := []string{}
	if !feasible {
		for _, p := range parents {
			if !assignment[p] {
				blockers = append(blockers, p)
			}
		}
		sort.Strings(blockers)
	}
	necessary := []string{}
	necessarySets := [][]string{}
	if feasible {
		necessary, err = m.NecessaryCauses(base, true)
		if err != nil {
			return false, []string{"scm_necessity_error"}, nil, nil, fmt.Errorf("compute necessary causes for %s: %w", rule.ID, err)
		}
		necessarySets, err = m.NecessaryCauseSets(base, true, maxSetSize)
		if err != nil {
			return false, []string{"scm_joint_necessity_error"}, nil, nil, fmt.Errorf("compute necessary cause sets for %s: %w", rule.ID, err)
		}
	}
	return feasible, blockers, necessary, necessarySets, nil
}

func reqPresence(index map[string][]int, rule Rule) map[string]bool {
	out := map[string]bool{}
	for _, req := range rule.Requirements {
		out[req.Type] = len(index[req.Type]) > 0
	}
	return out
}

func precondStatusMap(rule Rule, missing []model.EvidenceRequirement) map[string]bool {
	out := map[string]bool{}
	for _, p := range rule.Preconds {
		out[p] = true
	}
	for _, m := range missing {
		const a = "precond:"
		const b = "precond_order:"
		if len(m.Type) > len(a) && m.Type[:len(a)] == a {
			out[m.Type[len(a):]] = false
		}
		if len(m.Type) > len(b) && m.Type[:len(b)] == b {
			out[m.Type[len(b):]] = false
		}
	}
	return out
}

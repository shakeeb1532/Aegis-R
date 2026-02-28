package logic

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"aman/internal/causal"
)

var causalModelCache sync.Map

func evaluateRuleCausally(
	rule Rule,
	reqPresent map[string]bool,
	precondOK map[string]bool,
	gates map[string]bool,
	maxSetSize int,
) (bool, []string, []string, [][]string, error) {
	base := causal.Assignment{}

	reqVars := []string{}
	for _, req := range rule.Requirements {
		v := "req:" + req.Type
		reqVars = append(reqVars, v)
		base[v] = reqPresent[req.Type]
	}

	precondNames := allPrecondNames(rule)
	preVars := make([]string, 0, len(precondNames))
	for _, p := range precondNames {
		v := "pre:" + p
		preVars = append(preVars, v)
		base[v] = precondOK[p]
	}

	preVarsAnd := make([]string, 0, len(rule.Preconds))
	for _, p := range rule.Preconds {
		preVarsAnd = append(preVarsAnd, "pre:"+p)
	}

	groupDefs := buildPrecondGroupDefs(rule)
	groupVars := make([]string, 0, len(groupDefs))
	for _, g := range groupDefs {
		groupVars = append(groupVars, g.Var)
	}

	gateVars := []string{"gate:no_contradiction", "gate:context_ok", "gate:env_reachable", "gate:identity_priv_ok"}
	base[gateVars[0]] = gates["no_contradiction"]
	base[gateVars[1]] = gates["context_ok"]
	base[gateVars[2]] = gates["env_reachable"]
	base[gateVars[3]] = gates["identity_priv_ok"]

	parents := []string{}
	parents = append(parents, reqVars...)
	parents = append(parents, preVarsAnd...)
	parents = append(parents, groupVars...)
	parents = append(parents, gateVars...)
	terms := make([]causal.Expr, 0, len(parents))
	for _, p := range parents {
		terms = append(terms, causal.VarExpr{Name: p})
	}
	m, err := cachedCausalModel(rule, reqVars, preVars, groupDefs, gateVars, parents, terms)
	if err != nil {
		return false, []string{"scm_error"}, nil, nil, err
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

type precondGroupDef struct {
	Var     string
	Parents []string
}

func cachedCausalModel(
	rule Rule,
	reqVars []string,
	preVars []string,
	groupDefs []precondGroupDef,
	gateVars []string,
	parents []string,
	terms []causal.Expr,
) (causal.Model, error) {
	key := causalModelCacheKey(rule, reqVars, preVars, groupDefs)
	if v, ok := causalModelCache.Load(key); ok {
		if m, ok := v.(causal.Model); ok {
			return m, nil
		}
	}
	nodes := make([]causal.Node, 0, len(reqVars)+len(preVars)+len(groupDefs)+len(gateVars)+1)
	for _, v := range reqVars {
		nodes = append(nodes, causal.Node{Name: v, Exogenous: true})
	}
	for _, v := range preVars {
		nodes = append(nodes, causal.Node{Name: v, Exogenous: true})
	}
	for _, g := range groupDefs {
		terms := make([]causal.Expr, 0, len(g.Parents))
		for _, p := range g.Parents {
			terms = append(terms, causal.VarExpr{Name: p})
		}
		nodes = append(nodes, causal.Node{
			Name:     g.Var,
			Parents:  g.Parents,
			Equation: causal.OrExpr{Terms: terms},
		})
	}
	for _, v := range gateVars {
		nodes = append(nodes, causal.Node{Name: v, Exogenous: true})
	}
	nodes = append(nodes, causal.Node{
		Name:     "outcome:feasible",
		Parents:  parents,
		Equation: causal.AndExpr{Terms: terms},
	})
	m, err := causal.NewModel("outcome:feasible", nodes)
	if err != nil {
		return causal.Model{}, fmt.Errorf("build causal model for %s: %w", rule.ID, err)
	}
	causalModelCache.Store(key, m)
	return m, nil
}

func causalModelCacheKey(rule Rule, reqVars []string, preVars []string, groupDefs []precondGroupDef) string {
	b := strings.Builder{}
	b.WriteString(rule.ID)
	b.WriteString("|")
	b.WriteString(strings.Join(reqVars, ","))
	b.WriteString("|")
	b.WriteString(strings.Join(preVars, ","))
	if len(groupDefs) > 0 {
		parts := make([]string, 0, len(groupDefs))
		for _, g := range groupDefs {
			parts = append(parts, g.Var+"="+strings.Join(g.Parents, ","))
		}
		sort.Strings(parts)
		b.WriteString("|")
		b.WriteString(strings.Join(parts, ";"))
	}
	return b.String()
}

func reqPresence(index map[string][]int, rule Rule) map[string]bool {
	out := map[string]bool{}
	for _, req := range rule.Requirements {
		out[req.Type] = len(index[req.Type]) > 0
	}
	return out
}

func precondStatusMap(rule Rule, facts map[string]causalFact, requirementAt time.Time, hasRequirementTime bool, orderingJitter time.Duration) map[string]bool {
	out := map[string]bool{}
	for _, p := range allPrecondNames(rule) {
		ok, _ := precondSatisfied(p, facts, requirementAt, hasRequirementTime, orderingJitter)
		out[p] = ok
	}
	return out
}

func allPrecondNames(rule Rule) []string {
	seen := map[string]bool{}
	for _, p := range rule.Preconds {
		seen[p] = true
	}
	for _, group := range rule.PrecondGroups {
		for _, p := range group {
			seen[p] = true
		}
	}
	names := make([]string, 0, len(seen))
	for p := range seen {
		names = append(names, p)
	}
	sort.Strings(names)
	return names
}

func buildPrecondGroupDefs(rule Rule) []precondGroupDef {
	defs := make([]precondGroupDef, 0, len(rule.PrecondGroups))
	for i, group := range rule.PrecondGroups {
		if len(group) == 0 {
			continue
		}
		parents := make([]string, 0, len(group))
		for _, p := range group {
			parents = append(parents, "pre:"+p)
		}
		defs = append(defs, precondGroupDef{
			Var:     fmt.Sprintf("pre_any:%d", i),
			Parents: parents,
		})
	}
	return defs
}

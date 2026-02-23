package causal

import (
	"fmt"
	"sort"
)

type Assignment map[string]bool

type Expr interface {
	Eval(Assignment) bool
	Vars() []string
}

type VarExpr struct {
	Name string
}

func (v VarExpr) Eval(a Assignment) bool {
	return a[v.Name]
}

func (v VarExpr) Vars() []string {
	return []string{v.Name}
}

type NotExpr struct {
	X Expr
}

func (n NotExpr) Eval(a Assignment) bool {
	return !n.X.Eval(a)
}

func (n NotExpr) Vars() []string {
	return n.X.Vars()
}

type AndExpr struct {
	Terms []Expr
}

func (x AndExpr) Eval(a Assignment) bool {
	for _, t := range x.Terms {
		if !t.Eval(a) {
			return false
		}
	}
	return true
}

func (x AndExpr) Vars() []string {
	return gatherVars(x.Terms)
}

type OrExpr struct {
	Terms []Expr
}

func (x OrExpr) Eval(a Assignment) bool {
	for _, t := range x.Terms {
		if t.Eval(a) {
			return true
		}
	}
	return false
}

func (x OrExpr) Vars() []string {
	return gatherVars(x.Terms)
}

type Node struct {
	Name      string
	Parents   []string
	Equation  Expr
	Exogenous bool
}

type Model struct {
	Nodes   map[string]Node
	Outcome string
	order   []string
}

func NewModel(outcome string, nodes []Node) (Model, error) {
	m := Model{
		Nodes:   map[string]Node{},
		Outcome: outcome,
	}
	for _, n := range nodes {
		if n.Name == "" {
			return m, fmt.Errorf("%w: empty node name", ErrInvalidModel)
		}
		if _, ok := m.Nodes[n.Name]; ok {
			return m, fmt.Errorf("%w: duplicate node %s", ErrInvalidModel, n.Name)
		}
		m.Nodes[n.Name] = n
	}
	if _, ok := m.Nodes[outcome]; !ok {
		return m, fmt.Errorf("%w: missing outcome node %s", ErrInvalidModel, outcome)
	}
	for _, n := range m.Nodes {
		if n.Exogenous {
			continue
		}
		if n.Equation == nil {
			return m, fmt.Errorf("%w: node %s", ErrMissingEquation, n.Name)
		}
		allowed := map[string]bool{}
		for _, p := range n.Parents {
			allowed[p] = true
		}
		for _, v := range n.Equation.Vars() {
			if !allowed[v] {
				return m, fmt.Errorf("%w: equation var %s not declared parent of %s", ErrInvalidModel, v, n.Name)
			}
		}
	}
	order, err := topoOrder(m.Nodes)
	if err != nil {
		return m, err
	}
	m.order = order
	return m, nil
}

func (m Model) Evaluate(base Assignment, interventions Assignment) (Assignment, error) {
	if len(m.order) == 0 {
		return nil, ErrModelNotReady
	}
	out := Assignment{}
	for k, v := range base {
		out[k] = v
	}
	for _, name := range m.order {
		if interventions != nil {
			if v, ok := interventions[name]; ok {
				out[name] = v
				continue
			}
		}
		n := m.Nodes[name]
		if n.Exogenous {
			if _, ok := out[name]; !ok {
				out[name] = false
			}
			continue
		}
		if n.Equation == nil {
			return nil, fmt.Errorf("%w: %s", ErrMissingEquation, name)
		}
		out[name] = n.Equation.Eval(out)
	}
	return out, nil
}

func (m Model) OutcomeValue(a Assignment) (bool, error) {
	v, ok := a[m.Outcome]
	if !ok {
		return false, fmt.Errorf("%w: %s", ErrOutcomeNotPresent, m.Outcome)
	}
	return v, nil
}

func (m Model) NecessaryCauses(base Assignment, outcomeMustBe bool) ([]string, error) {
	actual, err := m.Evaluate(base, nil)
	if err != nil {
		return nil, err
	}
	outcome, err := m.OutcomeValue(actual)
	if err != nil {
		return nil, err
	}
	if outcome != outcomeMustBe {
		return []string{}, nil
	}
	causes := []string{}
	for _, name := range m.order {
		if name == m.Outcome {
			continue
		}
		current := actual[name]
		do := Assignment{name: !current}
		alt, err := m.Evaluate(base, do)
		if err != nil {
			return nil, err
		}
		altOutcome, err := m.OutcomeValue(alt)
		if err != nil {
			return nil, err
		}
		if altOutcome != outcomeMustBe {
			causes = append(causes, name)
		}
	}
	sort.Strings(causes)
	return causes, nil
}

// NecessaryCauseSets returns minimal cause sets (up to maxSetSize) whose
// counterfactual intervention flips the model outcome.
func (m Model) NecessaryCauseSets(base Assignment, outcomeMustBe bool, maxSetSize int) ([][]string, error) {
	if maxSetSize < 1 {
		maxSetSize = 1
	}
	actual, err := m.Evaluate(base, nil)
	if err != nil {
		return nil, err
	}
	outcome, err := m.OutcomeValue(actual)
	if err != nil {
		return nil, err
	}
	if outcome != outcomeMustBe {
		return [][]string{}, nil
	}

	candidates := []string{}
	for _, name := range m.order {
		if name == m.Outcome {
			continue
		}
		candidates = append(candidates, name)
	}
	sort.Strings(candidates)

	found := [][]string{}
	for size := 1; size <= maxSetSize; size++ {
		for _, combo := range combinations(candidates, size) {
			if hasSubset(found, combo) {
				continue
			}
			do := Assignment{}
			for _, name := range combo {
				do[name] = !actual[name]
			}
			alt, err := m.Evaluate(base, do)
			if err != nil {
				return nil, err
			}
			altOutcome, err := m.OutcomeValue(alt)
			if err != nil {
				return nil, err
			}
			if altOutcome != outcomeMustBe {
				cp := append([]string(nil), combo...)
				found = append(found, cp)
			}
		}
	}
	sort.Slice(found, func(i, j int) bool {
		if len(found[i]) != len(found[j]) {
			return len(found[i]) < len(found[j])
		}
		for k := 0; k < len(found[i]) && k < len(found[j]); k++ {
			if found[i][k] == found[j][k] {
				continue
			}
			return found[i][k] < found[j][k]
		}
		return false
	})
	return found, nil
}

func gatherVars(xs []Expr) []string {
	set := map[string]bool{}
	for _, x := range xs {
		for _, v := range x.Vars() {
			set[v] = true
		}
	}
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func topoOrder(nodes map[string]Node) ([]string, error) {
	vis := map[string]int{}
	out := []string{}
	var dfs func(string) error
	dfs = func(n string) error {
		switch vis[n] {
		case 1:
			return fmt.Errorf("%w: %s", ErrCycleDetected, n)
		case 2:
			return nil
		}
		vis[n] = 1
		node, ok := nodes[n]
		if !ok {
			return fmt.Errorf("%w: %s", ErrUnknownNode, n)
		}
		for _, p := range node.Parents {
			if _, ok := nodes[p]; !ok {
				return fmt.Errorf("%w: parent %s for %s", ErrUnknownNode, p, n)
			}
			if err := dfs(p); err != nil {
				return err
			}
		}
		vis[n] = 2
		out = append(out, n)
		return nil
	}
	keys := make([]string, 0, len(nodes))
	for k := range nodes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if err := dfs(k); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func combinations(items []string, k int) [][]string {
	if k <= 0 || k > len(items) {
		return nil
	}
	out := [][]string{}
	var walk func(start int, cur []string)
	walk = func(start int, cur []string) {
		if len(cur) == k {
			cp := append([]string(nil), cur...)
			out = append(out, cp)
			return
		}
		need := k - len(cur)
		for i := start; i <= len(items)-need; i++ {
			walk(i+1, append(cur, items[i]))
		}
	}
	walk(0, nil)
	return out
}

func hasSubset(sets [][]string, candidate []string) bool {
	for _, s := range sets {
		if len(s) > len(candidate) {
			continue
		}
		if isSubset(s, candidate) {
			return true
		}
	}
	return false
}

func isSubset(sub []string, set []string) bool {
	m := map[string]bool{}
	for _, v := range set {
		m[v] = true
	}
	for _, v := range sub {
		if !m[v] {
			return false
		}
	}
	return true
}

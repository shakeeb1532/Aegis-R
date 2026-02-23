package causal

import (
	"errors"
	"testing"
)

func TestModelEvaluateWithIntervention(t *testing.T) {
	nodes := []Node{
		{Name: "a", Exogenous: true},
		{Name: "b", Exogenous: true},
		{Name: "y", Parents: []string{"a", "b"}, Equation: AndExpr{Terms: []Expr{VarExpr{"a"}, VarExpr{"b"}}}},
	}
	m, err := NewModel("y", nodes)
	if err != nil {
		t.Fatalf("new model: %v", err)
	}
	base := Assignment{"a": true, "b": true}
	actual, err := m.Evaluate(base, nil)
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	if !actual["y"] {
		t.Fatalf("expected y=true")
	}
	intervened, err := m.Evaluate(base, Assignment{"a": false})
	if err != nil {
		t.Fatalf("eval with do: %v", err)
	}
	if intervened["y"] {
		t.Fatalf("expected y=false under do(a=false)")
	}
}

func TestModelNecessaryCauses(t *testing.T) {
	nodes := []Node{
		{Name: "a", Exogenous: true},
		{Name: "b", Exogenous: true},
		{Name: "y", Parents: []string{"a", "b"}, Equation: AndExpr{Terms: []Expr{VarExpr{"a"}, VarExpr{"b"}}}},
	}
	m, err := NewModel("y", nodes)
	if err != nil {
		t.Fatalf("new model: %v", err)
	}
	causes, err := m.NecessaryCauses(Assignment{"a": true, "b": true}, true)
	if err != nil {
		t.Fatalf("necessary: %v", err)
	}
	want := map[string]bool{"a": true, "b": true}
	for _, c := range causes {
		delete(want, c)
	}
	if len(want) != 0 {
		t.Fatalf("missing expected causes: %#v", want)
	}
}

func TestModelNecessaryCauseSets_JointCause(t *testing.T) {
	nodes := []Node{
		{Name: "a", Exogenous: true},
		{Name: "b", Exogenous: true},
		{Name: "y", Parents: []string{"a", "b"}, Equation: OrExpr{Terms: []Expr{VarExpr{"a"}, VarExpr{"b"}}}},
	}
	m, err := NewModel("y", nodes)
	if err != nil {
		t.Fatalf("new model: %v", err)
	}
	singles, err := m.NecessaryCauses(Assignment{"a": true, "b": true}, true)
	if err != nil {
		t.Fatalf("singles: %v", err)
	}
	// In OR with both true, neither single flip is necessary.
	if len(singles) != 0 {
		t.Fatalf("expected no single necessary causes, got %#v", singles)
	}

	sets, err := m.NecessaryCauseSets(Assignment{"a": true, "b": true}, true, 2)
	if err != nil {
		t.Fatalf("joint sets: %v", err)
	}
	if len(sets) == 0 {
		t.Fatalf("expected at least one necessary cause set")
	}
	if len(sets[0]) != 2 || sets[0][0] != "a" || sets[0][1] != "b" {
		t.Fatalf("expected joint cause set [a b], got %#v", sets[0])
	}
}

func TestModelNecessaryCauseSets_RejectsUnsafeSetSize(t *testing.T) {
	nodes := []Node{
		{Name: "a", Exogenous: true},
		{Name: "y", Parents: []string{"a"}, Equation: VarExpr{"a"}},
	}
	m, err := NewModel("y", nodes)
	if err != nil {
		t.Fatalf("new model: %v", err)
	}
	_, err = m.NecessaryCauseSets(Assignment{"a": true}, true, 10)
	if err == nil {
		t.Fatalf("expected safe bound error")
	}
	if !errors.Is(err, ErrCauseSetTooLarge) {
		t.Fatalf("expected ErrCauseSetTooLarge, got %v", err)
	}
}

func TestModelCycleRejected(t *testing.T) {
	_, err := NewModel("a", []Node{
		{Name: "a", Parents: []string{"b"}, Equation: VarExpr{"b"}},
		{Name: "b", Parents: []string{"a"}, Equation: VarExpr{"a"}},
	})
	if err == nil {
		t.Fatalf("expected cycle detection error")
	}
	if !errors.Is(err, ErrCycleDetected) {
		t.Fatalf("expected ErrCycleDetected, got %v", err)
	}
}

func TestModelEquationVarMustBeDeclaredParent(t *testing.T) {
	_, err := NewModel("y", []Node{
		{Name: "a", Exogenous: true},
		{Name: "b", Exogenous: true},
		{Name: "y", Parents: []string{"a"}, Equation: AndExpr{Terms: []Expr{VarExpr{"a"}, VarExpr{"b"}}}},
	})
	if err == nil {
		t.Fatalf("expected validation error")
	}
	if !errors.Is(err, ErrInvalidModel) {
		t.Fatalf("expected ErrInvalidModel, got %v", err)
	}
}

func TestModelNecessaryCausesSubsetOfParents(t *testing.T) {
	nodes := []Node{
		{Name: "a", Exogenous: true},
		{Name: "b", Exogenous: true},
		{Name: "y", Parents: []string{"a", "b"}, Equation: AndExpr{Terms: []Expr{VarExpr{"a"}, VarExpr{"b"}}}},
	}
	m, err := NewModel("y", nodes)
	if err != nil {
		t.Fatalf("new model: %v", err)
	}
	causes, err := m.NecessaryCauses(Assignment{"a": true, "b": true}, true)
	if err != nil {
		t.Fatalf("necessary: %v", err)
	}
	allowed := map[string]bool{"a": true, "b": true, "y": true}
	for _, c := range causes {
		if !allowed[c] {
			t.Fatalf("unexpected cause %s", c)
		}
	}
}

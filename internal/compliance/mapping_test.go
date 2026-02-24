package compliance

import (
	"reflect"
	"testing"

	"aman/internal/logic"
)

func TestExtractRuleIDsFromFindings(t *testing.T) {
	findings := []string{
		"TA0006.CREDDUMP feasible: ...",
		"TA0010.EXFIL incomplete: ...",
		"TA0006.CREDDUMP feasible again",
		"noise line",
	}
	got := ExtractRuleIDsFromFindings(findings)
	want := []string{"TA0006.CREDDUMP", "TA0010.EXFIL"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("rule ids mismatch: got=%v want=%v", got, want)
	}
}

func TestBuildRuleControlMappings(t *testing.T) {
	rules := []logic.Rule{
		{ID: "TA0006.CREDDUMP", Name: "Credential Dumping", NistCSF: []string{"DE.CM", "PR.AC"}},
	}
	got := BuildRuleControlMappings([]string{"TA0006.CREDDUMP"}, rules)
	if len(got) != 1 {
		t.Fatalf("expected 1 mapping, got %d", len(got))
	}
	if got[0].RuleID != "TA0006.CREDDUMP" {
		t.Fatalf("unexpected rule id %s", got[0].RuleID)
	}
	if len(got[0].Soc2CC) == 0 || len(got[0].ISO27001) == 0 {
		t.Fatalf("expected derived SOC2/ISO controls, got=%+v", got[0])
	}
}

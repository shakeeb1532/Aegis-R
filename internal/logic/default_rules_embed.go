package logic

import (
	_ "embed"
	"encoding/json"
)

//go:embed default_rules.json
var embeddedDefaultRules []byte

func loadEmbeddedDefaultRules() ([]Rule, error) {
	var rules []Rule
	if err := json.Unmarshal(embeddedDefaultRules, &rules); err != nil {
		return nil, err
	}
	if err := ValidateRules(rules); err != nil {
		return nil, err
	}
	return rules, nil
}

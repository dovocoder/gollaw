package config

import (
	"fmt"
	"os"

	"github.com/dovocoder/gollaw/internal/analyzer"
	"github.com/dovocoder/gollaw/internal/rulepack"
	"gopkg.in/yaml.v3"
)

// RulePackRef references a rule pack from config.
type RulePackRef struct {
	Name      string
	Enabled   bool
	Overrides map[string]int
}

// LoadRulePacks loads rule pack references from .gollaw.yaml.
func LoadRulePacks(configPath string) ([]RulePackRef, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	var raw struct {
		RulePacks []RulePackRef `yaml:"rule_packs"`
	}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	return raw.RulePacks, nil
}

// ResolveRulePacks resolves rule pack references to actual rules.
func ResolveRulePacks(refs []RulePackRef) ([]analyzer.Rule, error) {
	var rules []analyzer.Rule
	for _, ref := range refs {
		if !ref.Enabled {
			continue
		}
		pack, err := rulepack.GetPack(ref.Name)
		if err != nil {
			return nil, fmt.Errorf("rule pack %q: %w", ref.Name, err)
		}
		rules = append(rules, pack.Rules...)
	}
	return rules, nil
}

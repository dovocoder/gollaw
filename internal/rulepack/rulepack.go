// Package rulepack provides pluggable architecture rule packs that can be
// applied to a project's .gollaw.yaml configuration.
package rulepack

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/dovocoder/gollaw/internal/analyzer"
	"gopkg.in/yaml.v3"
)

// RulePack is a named collection of architecture rules and thresholds.
type RulePack struct {
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Rules       []analyzer.Rule  `json:"rules"`
	Thresholds  map[string]int   `json:"thresholds,omitempty"`
}

// BuiltInPacks returns all built-in rule packs.
func BuiltInPacks() []RulePack {
	return []RulePack{
		{
			Name:        "clean-architecture",
			Description: "Clean Architecture: domain must not depend on outer layers",
			Rules: []analyzer.Rule{
				{Package: "domain", MustNotUse: "infrastructure"},
				{Package: "domain", MustNotUse: "transport"},
				{Package: "usecase", MustNotUse: "transport"},
				{Package: "usecase", MustNotUse: "infrastructure"},
				{Package: "domain", MustNotUse: "usecase"},
			},
			Thresholds: map[string]int{
				"max-cyclomatic":    10,
				"max-function-lines": 40,
			},
		},
		{
			Name:        "hexagonal",
			Description: "Hexagonal Architecture (Ports & Adapters): ports must not depend on adapters",
			Rules: []analyzer.Rule{
				{Package: "ports", MustNotUse: "adapters"},
				{Package: "adapters", MustNotUse: "adapters"},
				{Package: "core", MustNotUse: "adapters"},
				{Package: "domain", MustNotUse: "adapters"},
			},
			Thresholds: map[string]int{
				"max-cyclomatic":    12,
				"max-function-lines": 50,
			},
		},
		{
			Name:        "microservice",
			Description: "Microservice boundaries: service layers must not leak across boundaries",
			Rules: []analyzer.Rule{
				{Package: "api", MustNotUse: "store"},
				{Package: "handler", MustNotUse: "repository"},
				{Package: "handler", MustNotUse: "store"},
				{Package: "service", MustNotUse: "handler"},
			},
			Thresholds: map[string]int{
				"max-cyclomatic":    15,
				"max-function-lines": 60,
			},
		},
		{
			Name:        "library",
			Description: "Library rules: no internal cycles, stable public API",
			Rules: []analyzer.Rule{
				{Package: "internal", MustNotUse: "internal"},
			},
			Thresholds: map[string]int{
				"max-cyclomatic":    10,
				"max-function-lines": 40,
				"min-dup-lines":      4,
			},
		},
		{
			Name:        "monolith",
			Description: "Standard layered monolith: handler → service → repository",
			Rules: []analyzer.Rule{
				{Package: "handler", MustNotUse: "repository"},
				{Package: "handler", MustNotUse: "model"},
				{Package: "repository", MustNotUse: "handler"},
				{Package: "model", MustNotUse: "handler"},
				{Package: "model", MustNotUse: "repository"},
			},
			Thresholds: map[string]int{
				"max-cyclomatic":    15,
				"max-cognitive":     20,
				"max-function-lines": 50,
			},
		},
	}
}

// GetPack returns the rule pack with the given name.
func GetPack(name string) (*RulePack, error) {
	for _, pack := range BuiltInPacks() {
		if pack.Name == name {
			return &pack, nil
		}
	}
	return nil, fmt.Errorf("unknown rule pack: %s (available: %s)", name, listPackNames())
}

// ApplyPack merges a rule pack's rules and thresholds into the project's
// .gollaw.yaml configuration file. If the file doesn't exist, it creates one.
func ApplyPack(name string, dir string) error {
	pack, err := GetPack(name)
	if err != nil {
		return err
	}

	configPath := filepath.Join(dir, ".gollaw.yaml")

	// Read existing config or create a new one.
	var cfg configYAML
	if data, err := os.ReadFile(configPath); err == nil {
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return fmt.Errorf("parse existing .gollaw.yaml: %w", err)
		}
	} else {
		// Create a default config.
		cfg = configYAML{
			Analyzers: analyzersYAML{
				Enabled:  []string{},
				Disabled: []string{},
			},
			Thresholds: thresholdsYAML{
				MaxCyclomatic:    15,
				MaxCognitive:     20,
				MaxFunctionLines: 50,
				MinDupLines:      6,
			},
			Rules:  []string{},
			Ignore: []string{"vendor/**", "**/*_test.go", "**/testdata/**"},
			Severity: severityYAML{Min: "hint"},
		}
	}

	// Merge pack rules into existing rules (avoid duplicates).
	existingRules := make(map[string]bool)
	for _, r := range cfg.Rules {
		existingRules[r] = true
	}
	for _, rule := range pack.Rules {
		ruleStr := fmt.Sprintf("%s must not import %s", rule.Package, rule.MustNotUse)
		if !existingRules[ruleStr] {
			cfg.Rules = append(cfg.Rules, ruleStr)
			existingRules[ruleStr] = true
		}
	}

	// Merge thresholds (pack thresholds override if higher specificity).
	if pack.Thresholds != nil {
		if v, ok := pack.Thresholds["max-cyclomatic"]; ok && v > 0 {
			cfg.Thresholds.MaxCyclomatic = v
		}
		if v, ok := pack.Thresholds["max-cognitive"]; ok && v > 0 {
			cfg.Thresholds.MaxCognitive = v
		}
		if v, ok := pack.Thresholds["max-function-lines"]; ok && v > 0 {
			cfg.Thresholds.MaxFunctionLines = v
		}
		if v, ok := pack.Thresholds["min-dup-lines"]; ok && v > 0 {
			cfg.Thresholds.MinDupLines = v
		}
	}

	// Write config back.
	data, err := yaml.Marshal(&cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	// Add a header comment.
	header := fmt.Sprintf("# .gollaw.yaml — rule pack '%s' applied\n", name)
	output := header + string(data)

	if err := os.WriteFile(configPath, []byte(output), 0o644); err != nil {
		return fmt.Errorf("write .gollaw.yaml: %w", err)
	}

	return nil
}

// listPackNames returns a comma-separated list of pack names.
func listPackNames() string {
	packs := BuiltInPacks()
	names := make([]string, len(packs))
	for i, p := range packs {
		names[i] = p.Name
	}
	return strings.Join(names, ", ")
}

// configYAML mirrors the .gollaw.yaml structure for reading/writing.
type configYAML struct {
	Analyzers  analyzersYAML   `yaml:"analyzers"`
	Thresholds thresholdsYAML  `yaml:"thresholds"`
	Rules      []string        `yaml:"rules"`
	Ignore     []string        `yaml:"ignore"`
	Severity   severityYAML    `yaml:"severity"`
}

type analyzersYAML struct {
	Enabled  []string `yaml:"enabled"`
	Disabled []string `yaml:"disabled"`
}

type thresholdsYAML struct {
	MaxCyclomatic    int `yaml:"max-cyclomatic"`
	MaxCognitive     int `yaml:"max-cognitive"`
	MaxFunctionLines int `yaml:"max-function-lines"`
	MinDupLines      int `yaml:"min-dup-lines"`
}

type severityYAML struct {
	Min string `yaml:"min"`
}

// FormatPacksText renders a list of rule packs as human-readable text.
func FormatPacksText(packs []RulePack) string {
	var b strings.Builder

	fmt.Fprintf(&b, "Rule Packs\n")
	fmt.Fprintf(&b, "%s\n", strings.Repeat("─", 50))

	for _, pack := range packs {
		fmt.Fprintf(&b, "\n%s — %s\n", pack.Name, pack.Description)
		if len(pack.Rules) > 0 {
			fmt.Fprintf(&b, "  Rules:\n")
			for _, r := range pack.Rules {
				fmt.Fprintf(&b, "    • %s must not import %s\n", r.Package, r.MustNotUse)
			}
		}
		if len(pack.Thresholds) > 0 {
			fmt.Fprintf(&b, "  Thresholds:\n")
			for k, v := range pack.Thresholds {
				fmt.Fprintf(&b, "    • %s: %d\n", k, v)
			}
		}
	}

	return b.String()
}



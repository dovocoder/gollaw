package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/dovocoder/gollaw/internal/analyzer"
	"gopkg.in/yaml.v3"
)

// configFile is the YAML representation of .gollaw.yaml.
type configFile struct {
	Analyzers  analyzersConfig  `yaml:"analyzers"`
	Thresholds thresholdsConfig `yaml:"thresholds"`
	Rules      []string         `yaml:"rules"`
	Ignore     []string         `yaml:"ignore"`
	Severity   severityConfig   `yaml:"severity"`
}

// analyzersConfig holds enabled/disabled analyzer lists.
type analyzersConfig struct {
	Enabled  []string `yaml:"enabled"`
	Disabled []string `yaml:"disabled"`
}

// thresholdsConfig holds complexity and duplication thresholds.
type thresholdsConfig struct {
	MaxCyclomatic    int `yaml:"max-cyclomatic"`
	MaxCognitive     int `yaml:"max-cognitive"`
	MaxFunctionLines int `yaml:"max-function-lines"`
	MinDupLines      int `yaml:"min-dup-lines"`
}

// severityConfig holds the minimum severity filter.
type severityConfig struct {
	Min string `yaml:"min"`
}

// Config is the resolved configuration combining file settings and ignore patterns.
//
//gollaw:ignore api-surface
type Config struct {
	Analyzers      analyzersConfig
	Thresholds     thresholdsConfig
	Rules          []string
	IgnorePatterns []string
	MinSeverity    analyzer.Severity
	// Path is the directory containing the loaded .gollaw.yaml (empty for defaults).
	Path string
}

const configFileName = ".gollaw.yaml"

// Default returns a Config with sensible default values.
//
//gollaw:ignore api-surface
func Default() *Config {
	return &Config{
		Analyzers: analyzersConfig{
			Enabled:  nil, // nil = all analyzers
			Disabled: nil,
		},
		Thresholds: thresholdsConfig{
			MaxCyclomatic:    15,
			MaxCognitive:     20,
			MaxFunctionLines: 50,
			MinDupLines:      6,
		},
		Rules:          nil,
		IgnorePatterns: []string{"vendor/**", "**/*_test.go", "**/testdata/**"},
		MinSeverity:    analyzer.SeverityWarning,
	}
}

// FindConfig walks up from dir until it finds .gollaw.yaml.
// Returns the full path if found, or empty string if not found.
func FindConfig(dir string) string {
	abs, err := filepath.Abs(dir)
	if err != nil {
		abs = dir
	}
	for {
		candidate := filepath.Join(abs, configFileName)
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
		parent := filepath.Dir(abs)
		if parent == abs {
			break
		}
		abs = parent
	}
	return ""
}

// Load reads .gollaw.yaml from the given path. If path is empty or refers
// to a directory, FindConfig is used to locate the file. If no file is
// found, Default() is returned without error.
func Load(path string) (*Config, error) {
	if path == "" {
		path = FindConfig(".")
	} else {
		if info, err := os.Stat(path); err == nil && info.IsDir() {
			path = FindConfig(path)
		}
	}
	if path == "" {
		d := Default()
		return d, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}

	var cf configFile
	if err := yaml.Unmarshal(data, &cf); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}

	cfg := fromConfigFile(cf)
	cfg.Path = filepath.Dir(path)
	return cfg, nil
}

// fromConfigFile converts the YAML representation into a Config, applying
// defaults for any zero-value fields.
func fromConfigFile(cf configFile) *Config {
	d := Default()

	if len(cf.Analyzers.Enabled) > 0 {
		d.Analyzers.Enabled = cf.Analyzers.Enabled
	}
	if len(cf.Analyzers.Disabled) > 0 {
		d.Analyzers.Disabled = cf.Analyzers.Disabled
	}

	if cf.Thresholds.MaxCyclomatic > 0 {
		d.Thresholds.MaxCyclomatic = cf.Thresholds.MaxCyclomatic
	}
	if cf.Thresholds.MaxCognitive > 0 {
		d.Thresholds.MaxCognitive = cf.Thresholds.MaxCognitive
	}
	if cf.Thresholds.MaxFunctionLines > 0 {
		d.Thresholds.MaxFunctionLines = cf.Thresholds.MaxFunctionLines
	}
	if cf.Thresholds.MinDupLines > 0 {
		d.Thresholds.MinDupLines = cf.Thresholds.MinDupLines
	}

	if len(cf.Rules) > 0 {
		d.Rules = cf.Rules
	}
	if len(cf.Ignore) > 0 {
		d.IgnorePatterns = cf.Ignore
	}
	if cf.Severity.Min != "" {
		d.MinSeverity = parseSeverity(cf.Severity.Min)
	}

	return d
}

// parseSeverity converts a string to analyzer.Severity, defaulting to hint.
func parseSeverity(s string) analyzer.Severity {
	switch strings.ToLower(s) {
	case "critical":
		return analyzer.SeverityCritical
	case "warning":
		return analyzer.SeverityWarning
	case "info":
		return analyzer.SeverityInfo
	case "hint":
		return analyzer.SeverityHint
	default:
		return analyzer.SeverityHint
	}
}

// Merge combines a file Config with a CLI-provided analyzer.Config.
// CLI values take precedence; file values fill in the gaps.
//
// Precedence rules:
//   - Analyzers: CLI list wins if non-empty, otherwise file enabled list.
//   - Rules: CLI rules win if non-empty, otherwise file rules.
//   - MinSeverity: CLI wins if non-empty, otherwise file value.
//   - Thresholds: CLI wins if non-zero, otherwise file value.
func Merge(cli analyzer.Config, file Config) analyzer.Config {
	merged := analyzer.Config{
		Analyzers:        cli.Analyzers,
		Rules:            cli.Rules,
		MinSeverity:      cli.MinSeverity,
		MaxCyclomatic:    cli.MaxCyclomatic,
		MaxCognitive:     cli.MaxCognitive,
		MaxFunctionLines: cli.MaxFunctionLines,
		MinDupLines:      cli.MinDupLines,
	}

	if len(merged.Analyzers) == 0 && len(file.Analyzers.Enabled) > 0 {
		merged.Analyzers = file.Analyzers.Enabled
	}
	if len(merged.Rules) == 0 {
		merged.Rules = parseRules(file.Rules)
	}
	if merged.MinSeverity == "" {
		merged.MinSeverity = file.MinSeverity
	}
	if merged.MaxCyclomatic == 0 {
		merged.MaxCyclomatic = file.Thresholds.MaxCyclomatic
	}
	if merged.MaxCognitive == 0 {
		merged.MaxCognitive = file.Thresholds.MaxCognitive
	}
	if merged.MaxFunctionLines == 0 {
		merged.MaxFunctionLines = file.Thresholds.MaxFunctionLines
	}
	if merged.MinDupLines == 0 {
		merged.MinDupLines = file.Thresholds.MinDupLines
	}

	// Remove disabled analyzers from the enabled list.
	if len(file.Analyzers.Disabled) > 0 {
		merged.Analyzers = removeDisabled(merged.Analyzers, file.Analyzers.Disabled)
	}

	return merged
}

// parseRules converts string rules like "internal/store must not import internal/api"
// into analyzer.Rule structs.
func parseRules(rules []string) []analyzer.Rule {
	var result []analyzer.Rule
	for _, r := range rules {
		// Expected format: "internal/store must not import internal/api"
		parts := strings.SplitN(r, " must not import ", 2)
		if len(parts) == 2 {
			result = append(result, analyzer.Rule{
				Package:    strings.TrimSpace(parts[0]),
				MustNotUse: strings.TrimSpace(parts[1]),
			})
		}
	}
	return result
}

// removeDisabled filters out disabled analyzer names from the enabled list.
// If enabled is empty (meaning "all"), the result is the disabled list negated
// — but since we don't know all analyzer names here, we return enabled as-is
// when it's empty (the caller must handle disabled at selection time).
func removeDisabled(enabled, disabled []string) []string {
	if len(enabled) == 0 {
		return enabled
	}
	disabledSet := make(map[string]bool, len(disabled))
	for _, d := range disabled {
		disabledSet[d] = true
	}
	var result []string
	for _, e := range enabled {
		if !disabledSet[e] {
			result = append(result, e)
		}
	}
	return result
}

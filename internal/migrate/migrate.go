// Package migrate provides migration from other Go linting tools' configs
// to gollaw's .gollaw.yaml format.
package migrate

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// MigrateResult holds the result of a migration.
type MigrateResult struct {
	Source    string   `json:"source"`
	Migrated  int      `json:"migrated"`
	Skipped   int      `json:"skipped"`
	Warnings  []string `json:"warnings"`
	Config    string   `json:"config"`
}

// configOutput is the YAML structure we generate.
type configOutput struct {
	Analyzers  analyzersOutput `yaml:"analyzers"`
	Thresholds thresholdsOutput `yaml:"thresholds"`
	Rules      []string        `yaml:"rules"`
	Ignore     []string        `yaml:"ignore"`
	Severity   severityOutput  `yaml:"severity"`
}

type analyzersOutput struct {
	Enabled  []string `yaml:"enabled"`
	Disabled []string `yaml:"disabled"`
}

type thresholdsOutput struct {
	MaxCyclomatic    int `yaml:"max-cyclomatic"`
	MaxCognitive     int `yaml:"max-cognitive"`
	MaxFunctionLines int `yaml:"max-function-lines"`
	MinDupLines      int `yaml:"min-dup-lines"`
}

type severityOutput struct {
	Min string `yaml:"min"`
}

// supportedSourceFiles maps source tool names to their config file names.
var supportedSourceFiles = map[string][]string{
	"staticcheck": {"staticcheck.conf", ".staticcheck.conf"},
	"golangci":    {".golangci.yml", ".golangci.yaml", ".golangci.toml"},
	"deadcode":    {".deadcode.yaml", ".deadcode.yml", "deadcode.yaml"},
}

// Migrate detects and migrates configuration from the given source tool.
// If source is "auto", all known config files are probed.
// Returns a MigrateResult with the generated .gollaw.yaml content.
func Migrate(source string, dir string) (*MigrateResult, error) {
	result := &MigrateResult{
		Source:   source,
		Warnings: []string{},
	}

	cfg := configOutput{
		Analyzers: analyzersOutput{
			Enabled:  []string{},
			Disabled: []string{},
		},
		Thresholds: thresholdsOutput{
			MaxCyclomatic:    15,
			MaxCognitive:     20,
			MaxFunctionLines: 50,
			MinDupLines:      6,
		},
		Ignore:   []string{"vendor/**", "**/*_test.go", "**/testdata/**"},
		Severity: severityOutput{Min: "hint"},
	}

	switch strings.ToLower(source) {
	case "staticcheck":
		migrated, skipped, warnings := migrateStaticcheck(dir, &cfg)
		result.Migrated = migrated
		result.Skipped = skipped
		result.Warnings = warnings
	case "golangci", "golangci-lint":
		migrated, skipped, warnings := migrateGolangCI(dir, &cfg)
		result.Migrated = migrated
		result.Skipped = skipped
		result.Warnings = warnings
	case "deadcode":
		migrated, skipped, warnings := migrateDeadcode(dir, &cfg)
		result.Migrated = migrated
		result.Skipped = skipped
		result.Warnings = warnings
	case "auto", "":
		// Try each source.
		totalMigrated, totalSkipped := 0, 0
		for _, src := range []string{"staticcheck", "golangci", "deadcode"} {
			m, s, w := doMigrate(src, dir, &cfg)
			totalMigrated += m
			totalSkipped += s
			result.Warnings = append(result.Warnings, w...)
		}
		result.Migrated = totalMigrated
		result.Skipped = totalSkipped
		if totalMigrated == 0 {
			result.Warnings = append(result.Warnings, "no known config files found in directory")
		}
	default:
		return nil, fmt.Errorf("unknown source: %s (use staticcheck, golangci, deadcode, or auto)", source)
	}

	// Generate YAML.
	data, err := yaml.Marshal(&cfg)
	if err != nil {
		return nil, fmt.Errorf("marshal config: %w", err)
	}
	result.Config = string(data)
	return result, nil
}

// doMigrate dispatches to the right migration function.
func doMigrate(source string, dir string, cfg *configOutput) (int, int, []string) {
	switch source {
	case "staticcheck":
		return migrateStaticcheck(dir, cfg)
	case "golangci":
		return migrateGolangCI(dir, cfg)
	case "deadcode":
		return migrateDeadcode(dir, cfg)
	default:
		return 0, 0, nil
	}
}

// findSourceFile searches for a config file in the given directory.
func findSourceFile(dir string, candidates []string) (string, error) {
	for _, name := range candidates {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("no config file found")
}

// migrateStaticcheck migrates staticcheck.conf to .gollaw.yaml settings.
func migrateStaticcheck(dir string, cfg *configOutput) (int, int, []string) {
	path, err := findSourceFile(dir, supportedSourceFiles["staticcheck"])
	if err != nil {
		return 0, 0, []string{"staticcheck.conf not found"}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, []string{fmt.Sprintf("read staticcheck.conf: %v", err)}
	}

	migrated := 0
	skipped := 0
	warnings := []string{}

	// staticcheck.conf format: lines like "checks = [\"SA1000\", \"ST1003\", ...]"
	// or key=value pairs.
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse checks list.
		if strings.HasPrefix(line, "checks") {
			checks := parseChecksList(line)
			for _, check := range checks {
				mapped := mapStaticcheckCheck(check)
				if mapped != "" {
					cfg.Analyzers.Enabled = append(cfg.Analyzers.Enabled, mapped)
					migrated++
				} else {
					skipped++
					warnings = append(warnings, fmt.Sprintf("no gollaw equivalent for staticcheck check: %s", check))
				}
			}
			continue
		}

		// Parse other settings.
		if strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(strings.Trim(parts[1], "\""))
			switch key {
			case "max_complexity":
				if n := parseIntSafe(value); n > 0 {
					cfg.Thresholds.MaxCyclomatic = n
					migrated++
				}
			case "min_confidence":
				migrated++
			default:
				skipped++
			}
		}
	}

	return migrated, skipped, warnings
}

// mapStaticcheckCheck maps a staticcheck check code to a gollaw analyzer name.
func mapStaticcheckCheck(check string) string {
	// staticcheck check prefixes: SA (static analysis), ST (style), S (quickfix),
	// ST1 (simplification), U (unused).
	switch {
	case strings.HasPrefix(check, "SA1"):
		return "deadcode" // SA1xxx = correctness checks (some overlap with dead code)
	case strings.HasPrefix(check, "SA5"):
		return "deadcode" // SA5xxx = correctness
	case strings.HasPrefix(check, "ST"):
		return "naming" // STxxx = style
	case strings.HasPrefix(check, "U"):
		return "unused" // Uxxx = unused
	case strings.HasPrefix(check, "S1"):
		return "complexity" // S1xxx = simplify
	default:
		return ""
	}
}

// parseChecksList extracts check names from a "checks = [...]" line.
func parseChecksList(line string) []string {
	// Find content within brackets.
	start := strings.Index(line, "[")
	end := strings.LastIndex(line, "]")
	if start < 0 || end < 0 || end <= start {
		return nil
	}
	content := line[start+1 : end]
	items := strings.Split(content, ",")
	var checks []string
	for _, item := range items {
		item = strings.TrimSpace(item)
		item = strings.Trim(item, "\"")
		if item != "" {
			checks = append(checks, item)
		}
	}
	return checks
}

// migrateGolangCI migrates .golangci.yml to .gollaw.yaml settings.
func migrateGolangCI(dir string, cfg *configOutput) (int, int, []string) {
	path, err := findSourceFile(dir, supportedSourceFiles["golangci"])
	if err != nil {
		return 0, 0, []string{".golangci.yml not found"}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, []string{fmt.Sprintf("read .golangci.yml: %v", err)}
	}

	// Parse as YAML (golangci-lint supports YAML, TOML, JSON — we handle YAML).
	var gc map[string]interface{}
	if err := yaml.Unmarshal(data, &gc); err != nil {
		return 0, 0, []string{fmt.Sprintf("parse .golangci.yml: %v", err)}
	}

	migrated := 0
	skipped := 0
	warnings := []string{}

	// Map linters.
	if linters, ok := gc["linters"].(map[string]interface{}); ok {
		if enabled, ok := linters["enable"].([]interface{}); ok {
			for _, l := range enabled {
				linter := fmt.Sprintf("%v", l)
				mapped := mapGolangCILinter(linter)
				if mapped != "" {
					cfg.Analyzers.Enabled = append(cfg.Analyzers.Enabled, mapped)
					migrated++
				} else {
					skipped++
					warnings = append(warnings, fmt.Sprintf("no gollaw equivalent for golangci-lint linter: %s", linter))
				}
			}
		}
		if disabled, ok := linters["disable"].([]interface{}); ok {
			for _, d := range disabled {
				linter := fmt.Sprintf("%v", d)
				mapped := mapGolangCILinter(linter)
				if mapped != "" {
					cfg.Analyzers.Disabled = append(cfg.Analyzers.Disabled, mapped)
					migrated++
				}
			}
		}
	}

	// Map severity.
	if sev, ok := gc["severity"].(map[string]interface{}); ok {
		if rules, ok := sev["rules"].([]interface{}); ok {
			for _, r := range rules {
				if ruleMap, ok := r.(map[string]interface{}); ok {
					if sev, ok := ruleMap["severity"].(string); ok {
						mapped := mapGolangCISeverity(sev)
						if mapped != "" {
							cfg.Severity.Min = mapped
							migrated++
							break
						}
					}
				}
			}
		}
	}

	// Map complexity thresholds.
	if lintersSettings, ok := gc["linters-settings"].(map[string]interface{}); ok {
		if gocyclo, ok := lintersSettings["gocyclo"].(map[string]interface{}); ok {
			if min, ok := gocyclo["min-complexity"].(int); ok && min > 0 {
				cfg.Thresholds.MaxCyclomatic = min
				migrated++
			}
		}
		if funlen, ok := lintersSettings["funlen"].(map[string]interface{}); ok {
			if lines, ok := funlen["lines"].(int); ok && lines > 0 {
				cfg.Thresholds.MaxFunctionLines = lines
				migrated++
			}
		}
		if dupl, ok := lintersSettings["dupl"].(map[string]interface{}); ok {
			if threshold, ok := dupl["threshold"].(int); ok && threshold > 0 {
				cfg.Thresholds.MinDupLines = threshold
				migrated++
			}
		}
	}

	return migrated, skipped, warnings
}

// mapGolangCILinter maps a golangci-lint linter name to a gollaw analyzer name.
func mapGolangCILinter(linter string) string {
	switch linter {
	case "deadcode":
		return "deadcode"
	case "unused":
		return "unused"
	case "gocyclo":
		return "complexity"
	case "gocognit":
		return "complexity"
	case "dupl":
		return "duplication"
	case "depguard":
		return "dependencies"
	case "gosec":
		return "security"
	case "funlen":
		return "large-functions"
	case "varcheck":
		return "unused"
	case "structcheck":
		return "unused"
	case "nakedret":
		return "thin-wrapper"
	case "gocritic":
		return "naming"
	case "goconst":
		return "duplication"
	case "misspell":
		return "naming"
	default:
		return ""
	}
}

// mapGolangCISeverity maps golangci-lint severity to gollaw severity.
func mapGolangCISeverity(sev string) string {
	switch strings.ToLower(sev) {
	case "error", "high":
		return "critical"
	case "warning", "medium":
		return "warning"
	case "info", "low":
		return "info"
	default:
		return ""
	}
}

// migrateDeadcode migrates deadcode config to .gollaw.yaml settings.
func migrateDeadcode(dir string, cfg *configOutput) (int, int, []string) {
	path, err := findSourceFile(dir, supportedSourceFiles["deadcode"])
	if err != nil {
		return 0, 0, []string{"deadcode config not found"}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, []string{fmt.Sprintf("read deadcode config: %v", err)}
	}

	// Parse as YAML.
	var dc map[string]interface{}
	if err := yaml.Unmarshal(data, &dc); err != nil {
		return 0, 0, []string{fmt.Sprintf("parse deadcode config: %v", err)}
	}

	migrated := 0
	skipped := 0
	warnings := []string{}

	// Enable the deadcode analyzer.
	cfg.Analyzers.Enabled = append(cfg.Analyzers.Enabled, "deadcode")
	migrated++

	// Map any file exclusions to ignore patterns.
	if exclude, ok := dc["exclude"].(interface{}); ok {
		switch v := exclude.(type) {
		case []interface{}:
			for _, e := range v {
				cfg.Ignore = append(cfg.Ignore, fmt.Sprintf("%v", e))
				migrated++
			}
		case string:
			cfg.Ignore = append(cfg.Ignore, v)
			migrated++
		}
	}

	// Map include patterns.
	if _, ok := dc["include"].(interface{}); ok {
		migrated++
	}

	return migrated, skipped, warnings
}

// parseIntSafe parses an integer from a string, returning 0 on failure.
func parseIntSafe(s string) int {
	var n int
	fmt.Sscanf(s, "%d", &n)
	return n
}

// FormatMigrateText renders a migration result as human-readable text.
func FormatMigrateText(result *MigrateResult) string {
	var b strings.Builder

	fmt.Fprintf(&b, "Migration Report — Source: %s\n", result.Source)
	fmt.Fprintf(&b, "%s\n", strings.Repeat("─", 50))
	fmt.Fprintf(&b, "Migrated: %d  |  Skipped: %d\n", result.Migrated, result.Skipped)

	if len(result.Warnings) > 0 {
		fmt.Fprintf(&b, "\nWarnings:\n")
		for _, w := range result.Warnings {
			fmt.Fprintf(&b, "  ⚠ %s\n", w)
		}
	}

	fmt.Fprintf(&b, "\nGenerated .gollaw.yaml:\n")
	fmt.Fprintf(&b, "%s\n", result.Config)

	return b.String()
}

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

// migrateResult holds the result of a migration.
type migrateResult struct {
	Source   string   `json:"source"`
	Migrated int      `json:"migrated"`
	Skipped  int      `json:"skipped"`
	Warnings []string `json:"warnings"`
	Config   string   `json:"config"`
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

// defaultConfig returns the initial configOutput with default values.
func defaultConfig() configOutput {
	return configOutput{
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
}

// Migrate detects and migrates configuration from the given source tool.
// If source is "auto", all known config files are probed.
// Returns a migrateResult with the generated .gollaw.yaml content.
func Migrate(source string, dir string) (*migrateResult, error) {
	result := &migrateResult{Source: source, Warnings: []string{}}
	cfg := defaultConfig()

	if err := dispatchMigration(source, dir, &cfg, result); err != nil {
		return nil, err
	}

	data, err := yaml.Marshal(&cfg)
	if err != nil {
		return nil, fmt.Errorf("marshal config: %w", err)
	}
	result.Config = string(data)
	return result, nil
}

// dispatchMigration routes to the appropriate migration function based on source.
func dispatchMigration(source string, dir string, cfg *configOutput, result *migrateResult) error {
	switch strings.ToLower(source) {
	case "staticcheck":
		m, s, w := migrateStaticcheck(dir, cfg)
		applyMigrationResult(result, m, s, w)
	case "golangci", "golangci-lint":
		m, s, w := migrateGolangCI(dir, cfg)
		applyMigrationResult(result, m, s, w)
	case "deadcode":
		m, s, w := migrateDeadcode(dir, cfg)
		applyMigrationResult(result, m, s, w)
	case "auto", "":
		runAutoMigration(dir, cfg, result)
	default:
		return fmt.Errorf("unknown source: %s (use staticcheck, golangci, deadcode, or auto)", source)
	}
	return nil
}

// applyMigrationResult stores migration counts and warnings into result.
func applyMigrationResult(result *migrateResult, migrated, skipped int, warnings []string) {
	result.Migrated = migrated
	result.Skipped = skipped
	result.Warnings = warnings
}

// runAutoMigration tries all known sources and accumulates results.
func runAutoMigration(dir string, cfg *configOutput, result *migrateResult) {
	totalMigrated, totalSkipped := 0, 0
	for _, src := range []string{"staticcheck", "golangci", "deadcode"} {
		m, s, w := doMigrate(src, dir, cfg)
		totalMigrated += m
		totalSkipped += s
		result.Warnings = append(result.Warnings, w...)
	}
	result.Migrated = totalMigrated
	result.Skipped = totalSkipped
	if totalMigrated == 0 {
		result.Warnings = append(result.Warnings, "no known config files found in directory")
	}
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

// readSourceFile reads a config file, returning warnings on error.
func readSourceFile(dir string, candidates []string, notFoundMsg string) ([]byte, []string) {
	path, err := findSourceFile(dir, candidates)
	if err != nil {
		return nil, []string{notFoundMsg}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, []string{fmt.Sprintf("read config: %v", err)}
	}
	return data, nil
}

// migrateStaticcheck migrates staticcheck.conf to .gollaw.yaml settings.
func migrateStaticcheck(dir string, cfg *configOutput) (int, int, []string) {
	data, warnings := readSourceFile(dir, supportedSourceFiles["staticcheck"], "staticcheck.conf not found")
	if data == nil {
		return 0, 0, warnings
	}

	migrated, skipped := 0, 0
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		m, s, w := parseStaticcheckLine(line, cfg)
		migrated += m
		skipped += s
		warnings = append(warnings, w...)
	}
	return migrated, skipped, warnings
}

// parseStaticcheckLine parses a single line of staticcheck.conf.
func parseStaticcheckLine(line string, cfg *configOutput) (int, int, []string) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return 0, 0, nil
	}
	if strings.HasPrefix(line, "checks") {
		return parseStaticcheckChecks(line, cfg)
	}
	if strings.Contains(line, "=") {
		return parseStaticcheckSetting(line, cfg)
	}
	return 0, 1, nil
}

// parseStaticcheckChecks parses a "checks = [...]" line and maps checks.
func parseStaticcheckChecks(line string, cfg *configOutput) (int, int, []string) {
	migrated, skipped := 0, 0
	var warnings []string
	for _, check := range parseChecksList(line) {
		mapped := mapStaticcheckCheck(check)
		if mapped != "" {
			cfg.Analyzers.Enabled = append(cfg.Analyzers.Enabled, mapped)
			migrated++
		} else {
			skipped++
			warnings = append(warnings, fmt.Sprintf("no gollaw equivalent for staticcheck check: %s", check))
		}
	}
	return migrated, skipped, warnings
}

// parseStaticcheckSetting parses a key=value setting line.
func parseStaticcheckSetting(line string, cfg *configOutput) (int, int, []string) {
	parts := strings.SplitN(line, "=", 2)
	key := strings.TrimSpace(parts[0])
	value := strings.TrimSpace(strings.Trim(parts[1], "\""))
	switch key {
	case "max_complexity":
		if n := parseIntSafe(value); n > 0 {
			cfg.Thresholds.MaxCyclomatic = n
			return 1, 0, nil
		}
	case "min_confidence":
		return 1, 0, nil
	}
	return 0, 1, nil
}

// mapStaticcheckCheck maps a staticcheck check code to a gollaw analyzer name.
func mapStaticcheckCheck(check string) string {
	switch {
	case strings.HasPrefix(check, "SA1"):
		return "deadcode"
	case strings.HasPrefix(check, "SA5"):
		return "deadcode"
	case strings.HasPrefix(check, "ST"):
		return "naming"
	case strings.HasPrefix(check, "U"):
		return "unused"
	case strings.HasPrefix(check, "S1"):
		return "complexity"
	default:
		return ""
	}
}

// parseChecksList extracts check names from a "checks = [...]" line.
func parseChecksList(line string) []string {
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
	data, warnings := readSourceFile(dir, supportedSourceFiles["golangci"], ".golangci.yml not found")
	if data == nil {
		return 0, 0, warnings
	}

	var gc map[string]interface{}
	if err := yaml.Unmarshal(data, &gc); err != nil {
		return 0, 0, []string{fmt.Sprintf("parse .golangci.yml: %v", err)}
	}

	migrated, skipped := 0, 0
	migrated += migrateGolangCILinters(gc, cfg)
	migrated += migrateGolangCISeverity(gc, cfg)
	migrated += migrateGolangCIThresholds(gc, cfg)
	return migrated, skipped, warnings
}

// migrateGolangCILinters maps enabled and disabled linters.
func migrateGolangCILinters(gc map[string]interface{}, cfg *configOutput) int {
	linters, ok := gc["linters"].(map[string]interface{})
	if !ok {
		return 0
	}
	migrated := 0
	migrated += mapLinterList(linters["enable"], &cfg.Analyzers.Enabled)
	migrated += mapLinterList(linters["disable"], &cfg.Analyzers.Disabled)
	return migrated
}

// mapLinterList maps a list of linters into the target slice, returning the migrated count.
func mapLinterList(raw interface{}, target *[]string) int {
	list, ok := raw.([]interface{})
	if !ok {
		return 0
	}
	migrated := 0
	for _, l := range list {
		linter := fmt.Sprintf("%v", l)
		mapped := mapGolangCILinter(linter)
		if mapped != "" {
			*target = append(*target, mapped)
			migrated++
		}
	}
	return migrated
}

// migrateGolangCISeverity maps the first severity rule found.
func migrateGolangCISeverity(gc map[string]interface{}, cfg *configOutput) int {
	sev, ok := gc["severity"].(map[string]interface{})
	if !ok {
		return 0
	}
	rules, ok := sev["rules"].([]interface{})
	if !ok {
		return 0
	}
	for _, r := range rules {
		ruleMap, ok := r.(map[string]interface{})
		if !ok {
			continue
		}
		sevVal, ok := ruleMap["severity"].(string)
		if !ok {
			continue
		}
		mapped := mapGolangCISeverity(sevVal)
		if mapped != "" {
			cfg.Severity.Min = mapped
			return 1
		}
	}
	return 0
}

// migrateGolangCIThresholds maps complexity and duplication thresholds.
func migrateGolangCIThresholds(gc map[string]interface{}, cfg *configOutput) int {
	settings, ok := gc["linters-settings"].(map[string]interface{})
	if !ok {
		return 0
	}
	migrated := 0
	migrated += extractIntSetting(settings, "gocyclo", "min-complexity", &cfg.Thresholds.MaxCyclomatic)
	migrated += extractIntSetting(settings, "funlen", "lines", &cfg.Thresholds.MaxFunctionLines)
	migrated += extractIntSetting(settings, "dupl", "threshold", &cfg.Thresholds.MinDupLines)
	return migrated
}

// extractIntSetting extracts an int value from a nested linters-settings entry.
func extractIntSetting(settings map[string]interface{}, tool, key string, target *int) int {
	toolMap, ok := settings[tool].(map[string]interface{})
	if !ok {
		return 0
	}
	val, ok := toolMap[key].(int)
	if !ok || val <= 0 {
		return 0
	}
	*target = val
	return 1
}

// mapGolangCILinter maps a golangci-lint linter name to a gollaw analyzer name.
func mapGolangCILinter(linter string) string {
	golangCILinterMap := map[string]string{
		"deadcode":     "deadcode",
		"unused":       "unused",
		"gocyclo":      "complexity",
		"gocognit":     "complexity",
		"dupl":         "duplication",
		"depguard":     "dependencies",
		"gosec":        "security",
		"funlen":       "large-functions",
		"varcheck":     "unused",
		"structcheck":  "unused",
		"nakedret":     "thin-wrapper",
		"gocritic":     "naming",
		"goconst":      "duplication",
		"misspell":     "naming",
	}
	if mapped, ok := golangCILinterMap[linter]; ok {
		return mapped
	}
	return ""
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
	data, warnings := readSourceFile(dir, supportedSourceFiles["deadcode"], "deadcode config not found")
	if data == nil {
		return 0, 0, warnings
	}

	var dc map[string]interface{}
	if err := yaml.Unmarshal(data, &dc); err != nil {
		return 0, 0, []string{fmt.Sprintf("parse deadcode config: %v", err)}
	}

	migrated := 0
	skipped := 0
	cfg.Analyzers.Enabled = append(cfg.Analyzers.Enabled, "deadcode")
	migrated++
	migrated += migrateDeadcodeExcludes(dc, cfg)
	if _, ok := dc["include"]; ok {
		migrated++
	}
	return migrated, skipped, warnings
}

// migrateDeadcodeExcludes maps exclude entries to ignore patterns.
func migrateDeadcodeExcludes(dc map[string]interface{}, cfg *configOutput) int {
	exclude, ok := dc["exclude"]
	if !ok {
		return 0
	}
	migrated := 0
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
	return migrated
}

// parseIntSafe parses an integer from a string, returning 0 on failure.
func parseIntSafe(s string) int {
	var n int
	fmt.Sscanf(s, "%d", &n)
	return n
}

// FormatMigrateText renders a migration result as human-readable text.
func FormatMigrateText(result *migrateResult) string {
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

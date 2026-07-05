// Package guard provides pre-edit architecture guidance.
// Given a file path, it reports which architecture rules apply before you edit it,
// and whether the file's package currently violates any rule.
package guard

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/dovocoder/gollaw/internal/analyzer"
)

// guardReport is the result of checking a file against architecture rules.
type guardReport struct {
	FilePath        string             `json:"filePath"`
	Exists          bool               `json:"exists"`
	Zone            string             `json:"zone"`
	ApplicableRules []guardRule        `json:"applicableRules"`
	Violations      []analyzer.Finding `json:"violations"`
}

// guardRule wraps an analyzer.Rule with display metadata.
type guardRule struct {
	Rule        analyzer.Rule `json:"rule"`
	Severity    string        `json:"severity"`
	Description string        `json:"description"`
}

// BuildGuardReport inspects a file path and determines which architecture
// rules apply to the file's package and whether the package currently
// violates any of those rules.
func BuildGuardReport(ctx *analyzer.Context, rules []analyzer.Rule, filePath string) (*guardReport, error) {
	report := &guardReport{FilePath: filePath}

	if abs, err := filepath.Abs(filePath); err == nil {
		filePath = abs
	}
	if info, err := os.Stat(filePath); err == nil && !info.IsDir() {
		report.Exists = true
	}

	pkgPath := findPkgForFile(ctx, filePath)
	report.Zone = pkgPath

	if pkgPath == "" {
		report.ApplicableRules = rulesToGuardRules(rules)
		return report, nil
	}

	report.ApplicableRules = applicableRulesForPkg(rules, pkgPath)
	report.Violations = findViolations(ctx, rules, pkgPath)
	return report, nil
}

// rulesToGuardRules converts all rules to guard rules (for awareness display).
func rulesToGuardRules(rules []analyzer.Rule) []guardRule {
	var result []guardRule
	for _, rule := range rules {
		result = append(result, makeGuardRule(rule))
	}
	return result
}

// applicableRulesForPkg returns guard rules that apply to the given package.
func applicableRulesForPkg(rules []analyzer.Rule, pkgPath string) []guardRule {
	var result []guardRule
	for _, rule := range rules {
		if ruleAppliesToPkg(rule, pkgPath) {
			result = append(result, makeGuardRule(rule))
		}
	}
	return result
}

// makeGuardRule creates a guardRule from an analyzer.Rule.
func makeGuardRule(rule analyzer.Rule) guardRule {
	return guardRule{
		Rule:        rule,
		Severity:    string(analyzer.SeverityCritical),
		Description: describeRule(rule),
	}
}

// FormatGuardText produces a human-readable guard report.
func FormatGuardText(report *guardReport) string {
	var b strings.Builder

	fmt.Fprintf(&b, "Guard Report for %s\n", report.FilePath)
	fmt.Fprintf(&b, "────────────────────────────────────\n")
	formatFileStatus(&b, report)
	formatZone(&b, report)

	fmt.Fprintf(&b, "\n")
	formatApplicableRules(&b, report.ApplicableRules)

	fmt.Fprintf(&b, "\n")
	formatViolationsText(&b, report.Violations)

	return b.String()
}

// formatFileStatus writes the file existence status.
func formatFileStatus(b *strings.Builder, report *guardReport) {
	if report.Exists {
		fmt.Fprintf(b, "File exists: yes\n")
	} else {
		fmt.Fprintf(b, "File exists: no (new file)\n")
	}
}

// formatZone writes the package zone information.
func formatZone(b *strings.Builder, report *guardReport) {
	if report.Zone != "" {
		fmt.Fprintf(b, "Package zone: %s\n", report.Zone)
	} else {
		fmt.Fprintf(b, "Package zone: unknown (file not in any analyzed package)\n")
	}
}

// formatApplicableRules writes the applicable rules section.
func formatApplicableRules(b *strings.Builder, rules []guardRule) {
	if len(rules) == 0 {
		fmt.Fprintf(b, "Applicable rules: none\n")
		return
	}
	fmt.Fprintf(b, "Applicable rules (%d):\n", len(rules))
	for i, gr := range rules {
		fmt.Fprintf(b, "  %d. [%s] %s\n", i+1, gr.Severity, gr.Description)
		fmt.Fprintf(b, "     package %q must not import %q\n", gr.Rule.Package, gr.Rule.MustNotUse)
	}
}

// formatViolationsText writes the violations section.
func formatViolationsText(b *strings.Builder, violations []analyzer.Finding) {
	if len(violations) == 0 {
		fmt.Fprintf(b, "Current violations: none — you're clear to edit.\n")
		return
	}
	fmt.Fprintf(b, "Current violations (%d):\n", len(violations))
	for _, v := range violations {
		fmt.Fprintf(b, "  [%s] %s:%d  %s\n", v.Severity, shortPath(v.File), v.Line, v.Message)
		if v.Detail != "" {
			fmt.Fprintf(b, "    %s\n", v.Detail)
		}
		if v.Suggestion != "" {
			fmt.Fprintf(b, "    → %s\n", v.Suggestion)
		}
	}
}

// FormatGuardJSON produces a JSON guard report.
//gollaw:ignore thin-wrappers
func FormatGuardJSON(report *guardReport) ([]byte, error) {
	return json.MarshalIndent(report, "", "  ")
}

// findPkgForFile walks the loaded packages and finds the one whose GoFiles
// contain the given file path.
func findPkgForFile(ctx *analyzer.Context, filePath string) string {
	abs, err := filepath.Abs(filePath)
	if err != nil {
		abs = filePath
	}
	for _, pkg := range ctx.Packages {
		for _, f := range pkg.GoFiles {
			if pathsMatch(f, abs) || pathsMatch(f, filePath) {
				return pkg.PkgPath
			}
		}
		for _, f := range pkg.CompiledGoFiles {
			if pathsMatch(f, abs) || pathsMatch(f, filePath) {
				return pkg.PkgPath
			}
		}
	}
	return ""
}

// pathsMatch checks if two file paths refer to the same file, handling
// relative vs absolute differences.
func pathsMatch(a, b string) bool {
	absA, errA := filepath.Abs(a)
	absB, errB := filepath.Abs(b)
	if errA == nil && errB == nil {
		return absA == absB
	}
	return a == b
}

// ruleAppliesToPkg returns true if the rule mentions the package (as source
// or target) using path-suffix matching consistent with the architecture analyzer.
func ruleAppliesToPkg(rule analyzer.Rule, pkgPath string) bool {
	return pkgHasSuffix(pkgPath, rule.Package) || pkgHasSuffix(pkgPath, rule.MustNotUse)
}

// describeRule produces a human-readable description of a rule.
//gollaw:ignore thin-wrappers
func describeRule(rule analyzer.Rule) string {
	return fmt.Sprintf("package %q must not import %q", rule.Package, rule.MustNotUse)
}

// findViolations runs the architecture boundary check for the given package
// against the rules, returning findings for any current violations.
func findViolations(ctx *analyzer.Context, rules []analyzer.Rule, pkgPath string) []analyzer.Finding {
	info := loadPkgImports(ctx, pkgPath)
	if info == nil {
		return nil
	}

	var violations []analyzer.Finding
	for _, rule := range rules {
		if !pkgHasSuffix(pkgPath, rule.Package) {
			continue
		}
		violations = append(violations, checkRuleViolations(rule, pkgPath, info)...)
	}
	return violations
}

// pkgImportInfo holds the imports and files of a loaded package.
type pkgImportInfo struct {
	Path    string
	Imports []string
	Files   []string
}

// loadPkgImports finds the loaded package matching pkgPath and extracts its imports.
func loadPkgImports(ctx *analyzer.Context, pkgPath string) *pkgImportInfo {
	for _, p := range ctx.Packages {
		if p.PkgPath != pkgPath {
			continue
		}
		info := &pkgImportInfo{Path: p.PkgPath, Files: p.GoFiles}
		for _, imp := range p.Imports {
			if imp != nil {
				info.Imports = append(info.Imports, imp.PkgPath)
			}
		}
		return info
	}
	return nil
}

// checkRuleViolations checks a single rule against the package's imports.
func checkRuleViolations(rule analyzer.Rule, pkgPath string, info *pkgImportInfo) []analyzer.Finding {
	var violations []analyzer.Finding
	for _, importedPath := range info.Imports {
		if !pkgHasSuffix(importedPath, rule.MustNotUse) {
			continue
		}
		violations = append(violations, makeViolation(rule, pkgPath, importedPath, info))
	}
	return violations
}

// makeViolation creates a Finding for an architecture violation.
func makeViolation(rule analyzer.Rule, pkgPath, importedPath string, info *pkgImportInfo) analyzer.Finding {
	file := ""
	if len(info.Files) > 0 {
		file = info.Files[0]
	}
	if file == "" {
		file = importedPath
	}
	return analyzer.Finding{
		Analyzer:   "guard",
		Category:   analyzer.CategoryArchitecture,
		Severity:   analyzer.SeverityCritical,
		Message:    fmt.Sprintf("architecture violation: %s imports %s", pkgPath, importedPath),
		Detail:     fmt.Sprintf("rule: %q must not import %q", rule.Package, rule.MustNotUse),
		File:       file,
		Line:       1,
		RuleID:     "GLW-AR001",
		Suggestion: fmt.Sprintf("Move the shared logic to a package that both %s and %s can import, or use an interface to invert the dependency.", rule.Package, rule.MustNotUse),
	}
}

// pkgHasSuffix checks if a package path ends with the given segment at a path boundary.
func pkgHasSuffix(pkgPath, suffix string) bool {
	if strings.HasSuffix(pkgPath, suffix) {
		if len(pkgPath) == len(suffix) || pkgPath[len(pkgPath)-len(suffix)-1] == '/' {
			return true
		}
	}
	return false
}

// shortPath returns the last 3 path components for compact display.
func shortPath(path string) string {
	parts := strings.Split(path, "/")
	if len(parts) <= 3 {
		return path
	}
	return strings.Join(parts[len(parts)-3:], "/")
}

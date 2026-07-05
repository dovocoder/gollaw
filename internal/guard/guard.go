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

// GuardReport is the result of checking a file against architecture rules.
//gollaw:keep
type GuardReport struct {
	FilePath        string            `json:"filePath"`
	Exists          bool             `json:"exists"`
	Zone            string           `json:"zone"`
	ApplicableRules []GuardRule      `json:"applicableRules"`
	Violations      []analyzer.Finding `json:"violations"`
}

// GuardRule wraps an analyzer.Rule with display metadata.
//gollaw:keep
type GuardRule struct {
	Rule        analyzer.Rule `json:"rule"`
	Severity    string        `json:"severity"`
	Description string        `json:"description"`
}

// BuildGuardReport inspects a file path and determines which architecture
// rules apply to the file's package and whether the package currently
// violates any of those rules.
func BuildGuardReport(ctx *analyzer.Context, rules []analyzer.Rule, filePath string) (*GuardReport, error) {
	report := &GuardReport{
		FilePath: filePath,
	}

	// Check file existence.
	if abs, err := filepath.Abs(filePath); err == nil {
		filePath = abs
	}
	if info, err := os.Stat(filePath); err == nil && !info.IsDir() {
		report.Exists = true
	}

	// Determine which package this file belongs to.
	pkgPath := findPkgForFile(ctx, filePath)
	report.Zone = pkgPath

	if pkgPath == "" {
		// Could not find the package — still list all rules for awareness.
		for _, rule := range rules {
			report.ApplicableRules = append(report.ApplicableRules, GuardRule{
				Rule:        rule,
				Severity:    string(analyzer.SeverityCritical),
				Description: describeRule(rule),
			})
		}
		return report, nil
	}

	// Find applicable rules: those mentioning this package as source or target.
	for _, rule := range rules {
		if ruleAppliesToPkg(rule, pkgPath) {
			report.ApplicableRules = append(report.ApplicableRules, GuardRule{
				Rule:        rule,
				Severity:    string(analyzer.SeverityCritical),
				Description: describeRule(rule),
			})
		}
	}

	// Check for current violations: run the architecture analysis logic inline.
	report.Violations = findViolations(ctx, rules, pkgPath)

	return report, nil
}

// FormatGuardText produces a human-readable guard report.
func FormatGuardText(report *GuardReport) string {
	var b strings.Builder

	fmt.Fprintf(&b, "Guard Report for %s\n", report.FilePath)
	fmt.Fprintf(&b, "────────────────────────────────────\n")
	if report.Exists {
		fmt.Fprintf(&b, "File exists: yes\n")
	} else {
		fmt.Fprintf(&b, "File exists: no (new file)\n")
	}
	if report.Zone != "" {
		fmt.Fprintf(&b, "Package zone: %s\n", report.Zone)
	} else {
		fmt.Fprintf(&b, "Package zone: unknown (file not in any analyzed package)\n")
	}

	fmt.Fprintf(&b, "\n")
	if len(report.ApplicableRules) == 0 {
		fmt.Fprintf(&b, "Applicable rules: none\n")
	} else {
		fmt.Fprintf(&b, "Applicable rules (%d):\n", len(report.ApplicableRules))
		for i, gr := range report.ApplicableRules {
			fmt.Fprintf(&b, "  %d. [%s] %s\n", i+1, gr.Severity, gr.Description)
			fmt.Fprintf(&b, "     package %q must not import %q\n", gr.Rule.Package, gr.Rule.MustNotUse)
		}
	}

	fmt.Fprintf(&b, "\n")
	if len(report.Violations) == 0 {
		fmt.Fprintf(&b, "Current violations: none — you're clear to edit.\n")
	} else {
		fmt.Fprintf(&b, "Current violations (%d):\n", len(report.Violations))
		for _, v := range report.Violations {
			fmt.Fprintf(&b, "  [%s] %s:%d  %s\n", v.Severity, shortPath(v.File), v.Line, v.Message)
			if v.Detail != "" {
				fmt.Fprintf(&b, "    %s\n", v.Detail)
			}
			if v.Suggestion != "" {
				fmt.Fprintf(&b, "    → %s\n", v.Suggestion)
			}
		}
	}

	return b.String()
}

// FormatGuardJSON produces a JSON guard report.
func FormatGuardJSON(report *GuardReport) ([]byte, error) {
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
func describeRule(rule analyzer.Rule) string {
	return fmt.Sprintf("package %q must not import %q", rule.Package, rule.MustNotUse)
}

// findViolations runs the architecture boundary check for the given package
// against the rules, returning findings for any current violations.
func findViolations(ctx *analyzer.Context, rules []analyzer.Rule, pkgPath string) []analyzer.Finding {
	var violations []analyzer.Finding

	// Find the loaded package matching pkgPath.
	type pkgInfo struct {
		Path    string
		Imports []string
		Files   []string
	}
	var info *pkgInfo
	for _, p := range ctx.Packages {
		if p.PkgPath != pkgPath {
			continue
		}
		pi := &pkgInfo{Path: p.PkgPath, Files: p.GoFiles}
		for _, imp := range p.Imports {
			if imp != nil {
				pi.Imports = append(pi.Imports, imp.PkgPath)
			}
		}
		info = pi
		break
	}
	if info == nil {
		return nil
	}

	for _, rule := range rules {
		// Does this rule's source match the file's package?
		if !pkgHasSuffix(pkgPath, rule.Package) {
			// Also check if this package imports a forbidden target.
			// Even if the rule's source is a different package, if *this*
			// package imports the forbidden target it may be relevant context.
			// But for violations, only flag if the source matches.
			continue
		}
		for _, importedPath := range info.Imports {
			if pkgHasSuffix(importedPath, rule.MustNotUse) {
				file := ""
				if len(info.Files) > 0 {
					file = info.Files[0]
				}
				if file == "" {
					file = importedPath
				}
				violations = append(violations, analyzer.Finding{
					Analyzer:  "guard",
					Category:  analyzer.CategoryArchitecture,
					Severity:  analyzer.SeverityCritical,
					Message:   fmt.Sprintf("architecture violation: %s imports %s", pkgPath, importedPath),
					Detail:    fmt.Sprintf("rule: %q must not import %q", rule.Package, rule.MustNotUse),
					File:      file,
					Line:      1,
					RuleID:    "GLW-AR001",
					Suggestion: fmt.Sprintf("Move the shared logic to a package that both %s and %s can import, or use an interface to invert the dependency.", rule.Package, rule.MustNotUse),
				})
			}
		}
	}

	return violations
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

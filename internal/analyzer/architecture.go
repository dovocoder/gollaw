package analyzer

import (
	"fmt"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"
)

// architectureAnalyzer checks user-defined architecture boundary rules.
type architectureAnalyzer struct{}

func newArchitectureAnalyzer() *architectureAnalyzer { return &architectureAnalyzer{} }

func (a *architectureAnalyzer) Name() string        { return "architecture" }
func (a *architectureAnalyzer) Category() Category  { return CategoryArchitecture }
func (a *architectureAnalyzer) Description() string { return "Architecture boundary violations" }

func (a *architectureAnalyzer) Analyze(ctx *Context) ([]Finding, error) {
	if len(ctx.Config.Rules) == 0 {
		return nil, nil
	}

	var findings []Finding
	for _, rule := range ctx.Config.Rules {
		findings = append(findings, a.checkRule(ctx, rule)...)
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].File != findings[j].File {
			return findings[i].File < findings[j].File
		}
		return findings[i].Line < findings[j].Line
	})

	return findings, nil
}

// checkRule checks all packages against a single architecture rule.
func (a *architectureAnalyzer) checkRule(ctx *Context, rule Rule) []Finding {
	var findings []Finding
	for _, pkg := range ctx.Packages {
		if !pkgHasSuffix(pkg.PkgPath, rule.Package) {
			continue
		}
		findings = append(findings, a.checkPackageImports(ctx, pkg, rule)...)
	}
	return findings
}

// checkPackageImports checks a single package's imports against a rule.
func (a *architectureAnalyzer) checkPackageImports(ctx *Context, pkg *packages.Package, rule Rule) []Finding {
	var findings []Finding
	for _, imported := range pkg.Imports {
		if imported == nil || !pkgHasSuffix(imported.PkgPath, rule.MustNotUse) {
			continue
		}
		findings = append(findings, a.createViolationFinding(pkg, imported.PkgPath, rule))
	}
	return findings
}

// createViolationFinding builds a Finding for a single architecture violation.
func (a *architectureAnalyzer) createViolationFinding(pkg *packages.Package, importedPath string, rule Rule) Finding {
	file := pkgPathFile(pkg.GoFiles)
	if file == "" {
		file = importedPath
	}
	return Finding{
		Analyzer:   a.Name(),
		Category:   a.Category(),
		Severity:   SeverityCritical,
		Message:     fmt.Sprintf("architecture violation: %s imports %s", pkg.PkgPath, importedPath),
		Detail:      fmt.Sprintf("rule: %q must not import %q", rule.Package, rule.MustNotUse),
		File:        file,
		Line:        1,
		RuleID:      "GLW-AR001",
		Suggestion:  fmt.Sprintf("Move the shared logic to a package that both %s and %s can import, or use an interface to invert the dependency.", rule.Package, rule.MustNotUse),
	}
}

func pkgPathFile(files []string) string {
	if len(files) > 0 {
		return files[0]
	}
	return ""
}

// pkgHasSuffix checks if a package path ends with the given segment.
// e.g. pkgHasSuffix("github.com/foo/internal/cli", "internal/cli") → true
func pkgHasSuffix(pkgPath, suffix string) bool {
	if strings.HasSuffix(pkgPath, suffix) {
		// Ensure it's a path boundary, not a partial match.
		if len(pkgPath) == len(suffix) || pkgPath[len(pkgPath)-len(suffix)-1] == '/' {
			return true
		}
	}
	return false
}

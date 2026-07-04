package analyzer

import (
	"fmt"
	"sort"
	"strings"
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
		// rule: package "rule.Package" must not import "rule.MustNotUse"
		// Match on path suffix so users can write "internal/cli" instead of
		// the full "github.com/dovocoder/gollaw/internal/cli".
		for _, pkg := range ctx.Packages {
			if !pkgHasSuffix(pkg.PkgPath, rule.Package) {
				continue
			}
			for _, imported := range pkg.Imports {
				if imported == nil {
					continue
				}
				if pkgHasSuffix(imported.PkgPath, rule.MustNotUse) {
					file := pkgPathFile(pkg.GoFiles)
					if file == "" {
						file = imported.PkgPath
					}
					findings = append(findings, Finding{
						Analyzer:  a.Name(),
						Category:  a.Category(),
						Severity:  SeverityCritical,
						Message:    fmt.Sprintf("architecture violation: %s imports %s", pkg.PkgPath, imported.PkgPath),
						Detail:     fmt.Sprintf("rule: %q must not import %q", rule.Package, rule.MustNotUse),
						File:       file,
						Line:       1,
						RuleID:     "GLW-AR001",
						Suggestion: fmt.Sprintf("Move the shared logic to a package that both %s and %s can import, or use an interface to invert the dependency.", rule.Package, rule.MustNotUse),
					})
				}
			}
		}
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].File != findings[j].File {
			return findings[i].File < findings[j].File
		}
		return findings[i].Line < findings[j].Line
	})

	return findings, nil
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

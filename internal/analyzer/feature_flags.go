package analyzer

import (
	"go/ast"
	"strings"
)

// featureFlagsAnalyzer finds build tags and feature gates that may guard dead code.
type featureFlagsAnalyzer struct{}

func newFeatureFlagsAnalyzer() *featureFlagsAnalyzer { return &featureFlagsAnalyzer{} }

func (a *featureFlagsAnalyzer) Name() string        { return "feature-flags" }
func (a *featureFlagsAnalyzer) Category() Category   { return CategoryCodeSmell }
func (a *featureFlagsAnalyzer) Description() string  { return "Finds build tags and feature gates that may guard dead code" }

func (a *featureFlagsAnalyzer) Analyze(ctx *Context) ([]Finding, error) {
	var findings []Finding
	for _, files := range ctx.SyntaxByPkg {
		for _, file := range files {
			for _, cg := range file.Comments {
				text := cg.Text()
				if strings.Contains(text, "//go:build") || strings.Contains(text, "// +build") {
					tag := extractBuildTag(text)
					findings = append(findings, Finding{
						Analyzer:  a.Name(),
						Category:  CategoryCodeSmell,
						Severity:  SeverityInfo,
						Message:    "file guarded by build tag: " + tag,
						Detail:     "Functions in this file may be dead in the current build configuration.",
						File:       ctx.FSET.Position(file.Pos()).Filename,
						Line:       ctx.FSET.Position(cg.Pos()).Line,
						Suggestion: "Verify that code behind this build tag is still needed",
						RuleID:     "GLW-FF001",
					})
				}
			}
			ast.Inspect(file, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok {
					if se, ok := call.Fun.(*ast.SelectorExpr); ok {
						if ident, ok := se.X.(*ast.Ident); ok {
							fn := se.Sel.Name
							if (ident.Name == "os" && fn == "Getenv") || (ident.Name == "flag" && (fn == "Bool" || fn == "String" || fn == "Int")) {
								if len(call.Args) > 0 {
									if lit, ok := call.Args[0].(*ast.BasicLit); ok {
										flagName := strings.Trim(lit.Value, `"`)
										pos := ctx.FSET.Position(call.Pos())
										findings = append(findings, Finding{
											Analyzer:  a.Name(),
											Category:  CategoryCodeSmell,
											Severity:  SeverityInfo,
											Message:    "feature gate via " + ident.Name + "." + fn + `("` + flagName + `")`,
											Detail:     "This env var or flag gates code. If the gate is never set, the guarded code may be dead.",
											File:       pos.Filename,
											Line:       pos.Line,
											Suggestion: "Consider using build tags instead of runtime flags for dead code elimination",
											RuleID:     "GLW-FF002",
										})
									}
								}
							}
						}
					}
				}
				return true
			})
		}
	}
	return findings, nil
}

func extractBuildTag(commentText string) string {
	for _, line := range strings.Split(commentText, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "//go:build") {
			return strings.TrimPrefix(line, "//go:build")
		}
		if strings.HasPrefix(line, "// +build") {
			return strings.TrimPrefix(line, "// +build")
		}
	}
	return "unknown"
}

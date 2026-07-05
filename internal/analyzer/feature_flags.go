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
			findings = append(findings, a.checkBuildTags(ctx, file)...)
			findings = append(findings, a.checkFeatureGates(ctx, file)...)
		}
	}
	return findings, nil
}

// checkBuildTags scans file comments for conditional-compilation directives.
func (a *featureFlagsAnalyzer) checkBuildTags(ctx *Context, file *ast.File) []Finding {
	var findings []Finding
	for _, cg := range file.Comments {
		text := cg.Text()
		if strings.Contains(text, "//go:build") || strings.Contains(text, "// +build") {
			tag := extractBuildTag(text)
			findings = append(findings, Finding{
				Analyzer:   a.Name(),
				Category:   CategoryCodeSmell,
				Severity:   SeverityInfo,
				Message:     "file guarded by build tag: " + tag,
				Detail:      "Functions in this file may be dead in the current build configuration.",
				File:        ctx.FSET.Position(file.Pos()).Filename,
				Line:        ctx.FSET.Position(cg.Pos()).Line,
				Suggestion:  "Verify that code behind this build tag is still needed",
				RuleID:      "GLW-FF001",
			})
		}
	}
	return findings
}

// checkFeatureGates scans for os.Getenv and flag.X() calls used as runtime gates.
func (a *featureFlagsAnalyzer) checkFeatureGates(ctx *Context, file *ast.File) []Finding {
	var findings []Finding
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		se, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		ident, ok := se.X.(*ast.Ident)
		if !ok {
			return true
		}
		fn := se.Sel.Name
		if !isFeatureGateCall(ident.Name, fn) {
			return true
		}
		findings = append(findings, a.checkFeatureGateArgs(ctx, call, ident.Name, fn)...)
		return true
	})
	return findings
}

// isFeatureGateCall returns true for os.Getenv and flag.Bool/String/Int calls.
//gollaw:keep
func isFeatureGateCall(pkgName, fnName string) bool {
	if pkgName == "os" && fnName == "Getenv" {
		return true
	}
	if pkgName == "flag" {
		switch fnName {
		case "Bool", "String", "Int":
			return true
		}
	}
	return false
}

// checkFeatureGateArgs checks call arguments for a string literal flag name.
func (a *featureFlagsAnalyzer) checkFeatureGateArgs(ctx *Context, call *ast.CallExpr, pkgName, fn string) []Finding {
	if len(call.Args) == 0 {
		return nil
	}
	lit, ok := call.Args[0].(*ast.BasicLit)
	if !ok {
		return nil
	}
	flagName := strings.Trim(lit.Value, `"`)
	pos := ctx.FSET.Position(call.Pos())
	return []Finding{{
		Analyzer:   a.Name(),
		Category:   CategoryCodeSmell,
		Severity:   SeverityInfo,
		Message:     "feature gate via " + pkgName + "." + fn + `("` + flagName + `")`,
		Detail:      "This env var or flag gates code. If the gate is never set, the guarded code may be dead.",
		File:        pos.Filename,
		Line:        pos.Line,
		Suggestion:  "Consider using build tags instead of runtime flags for dead code elimination",
		RuleID:      "GLW-FF002",
	}}
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

package analyzer

import (
	"go/ast"
	"strings"
)

// featureFlagsAnalyzer finds build tags and feature gates that may guard dead code.
type featureFlagsAnalyzer struct{}

func newFeatureFlagsAnalyzer() *featureFlagsAnalyzer { return &featureFlagsAnalyzer{} }

func (a *featureFlagsAnalyzer) Name() string       { return "feature-flags" }
func (a *featureFlagsAnalyzer) Category() Category { return CategoryCodeSmell }
func (a *featureFlagsAnalyzer) Description() string {
	return "Finds build tags and feature gates that may guard dead code"
}

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
		if cg.Pos() > file.Package {
			continue
		}
		tag, ok := leadingBuildTag(cg)
		if !ok {
			continue
		}
		findings = append(findings, Finding{
			Analyzer:   a.Name(),
			Category:   CategoryCodeSmell,
			Severity:   SeverityInfo,
			Message:    "file guarded by build tag: " + tag,
			Detail:     "Functions in this file may be dead in the current build configuration.",
			File:       ctx.FSET.Position(file.Pos()).Filename,
			Line:       ctx.FSET.Position(cg.Pos()).Line,
			Suggestion: "Verify that code behind this build tag is still needed",
			RuleID:     "GLW-FF001",
		})
	}
	return findings
}

// checkFeatureGates scans for os.Getenv and flag.X() calls used as runtime
// feature gates. Only flags calls that appear within a conditional expression
// (if/switch/for condition), not calls used as config values (assignments,
// function arguments, struct fields).
func (a *featureFlagsAnalyzer) checkFeatureGates(ctx *Context, file *ast.File) []Finding {
	// Collect all condition expressions in the file — these are the
	// Cond of IfStmt, Tag of SwitchStmt, and Cond of ForStmt.
	// A feature gate call is only flagged if it appears within one of these.
	conditions := collectConditionExprs(file)

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
		// Only flag if the call is within a condition expression.
		callPos := call.Pos()
		for _, cond := range conditions {
			if callPos >= cond.Pos() && callPos <= cond.End() {
				findings = append(findings, a.checkFeatureGateArgs(ctx, call, ident.Name, fn)...)
				break
			}
		}
		return true
	})
	return findings
}

// collectConditionExprs returns all expressions used as conditions in
// if/switch/for statements in the file. These are the expressions where
// a feature gate actually gates code — an os.Getenv in an assignment is
// a config value, not a gate.
func collectConditionExprs(file *ast.File) []ast.Expr {
	var conds []ast.Expr
	ast.Inspect(file, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.IfStmt:
			if s.Cond != nil {
				conds = append(conds, s.Cond)
			}
		case *ast.SwitchStmt:
			if s.Tag != nil {
				conds = append(conds, s.Tag)
			}
		case *ast.ForStmt:
			if s.Cond != nil {
				conds = append(conds, s.Cond)
			}
		case *ast.CaseClause:
			// case expressions in a switch are also conditions
			for _, expr := range s.List {
				conds = append(conds, expr)
			}
		}
		return true
	})
	return conds
}

// isFeatureGateCall returns true for os.Getenv and flag.Bool/String/Int calls.
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
	if isOperationalEnvGate(flagName) {
		return nil
	}
	pos := ctx.FSET.Position(call.Pos())
	return []Finding{{
		Analyzer:   a.Name(),
		Category:   CategoryCodeSmell,
		Severity:   SeverityInfo,
		Message:    "feature gate via " + pkgName + "." + fn + `("` + flagName + `")`,
		Detail:     "This env var or flag gates code. If the gate is never set, the guarded code may be dead.",
		File:       pos.Filename,
		Line:       pos.Line,
		Suggestion: "Consider using build tags instead of runtime flags for dead code elimination",
		RuleID:     "GLW-FF002",
	}}
}

func isOperationalEnvGate(name string) bool {
	upper := strings.ToUpper(strings.TrimSpace(name))
	return strings.HasSuffix(upper, "_READONLY") ||
		strings.HasSuffix(upper, "_READ_ONLY") ||
		strings.HasSuffix(upper, "_DEBUG") ||
		strings.HasSuffix(upper, "_VERBOSE")
}

func leadingBuildTag(cg *ast.CommentGroup) (string, bool) {
	for _, comment := range cg.List {
		line := strings.TrimSpace(comment.Text)
		switch {
		case strings.HasPrefix(line, "//go:build"):
			return strings.TrimSpace(strings.TrimPrefix(line, "//go:build")), true
		case strings.HasPrefix(line, "// +build"):
			return strings.TrimSpace(strings.TrimPrefix(line, "// +build")), true
		}
	}
	return "", false
}

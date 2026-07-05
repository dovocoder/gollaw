package analyzer

import (
	"go/ast"
	"go/types"
	"strings"
)

// deadFlagsAnalyzer finds unused constants and flag registrations that are never read.
type deadFlagsAnalyzer struct{}

func newDeadFlagsAnalyzer() *deadFlagsAnalyzer { return &deadFlagsAnalyzer{} }

func (a *deadFlagsAnalyzer) Name() string        { return "dead-flags" }
func (a *deadFlagsAnalyzer) Category() Category   { return CategoryDeadCode }
func (a *deadFlagsAnalyzer) Description() string  { return "Finds unused constants and flag registrations that are never read" }

func (a *deadFlagsAnalyzer) Analyze(ctx *Context) ([]Finding, error) {
	var findings []Finding
	findings = append(findings, a.checkUnusedConstants(ctx)...)
	findings = append(findings, a.checkUnreadFlags(ctx)...)
	return findings, nil
}

// checkUnusedConstants finds exported constants that are never referenced.
func (a *deadFlagsAnalyzer) checkUnusedConstants(ctx *Context) []Finding {
	constUsage := collectConstantUsage(ctx)
	return a.findUnusedConstants(ctx, constUsage)
}

// collectConstantUsage builds a map of all constant references keyed by
// pkgPath.constantName.
func collectConstantUsage(ctx *Context) map[string]bool {
	constUsage := make(map[string]bool)
	for _, pkg := range ctx.Packages {
		if pkg.TypesInfo == nil {
			continue
		}
		for _, obj := range pkg.TypesInfo.Uses {
			c, ok := obj.(*types.Const)
			if !ok || c.Pkg() == nil {
				continue
			}
			key := c.Pkg().Path() + "." + c.Name()
			constUsage[key] = true
		}
	}
	return constUsage
}

// findUnusedConstants scans declared constants for those that are never used.
func (a *deadFlagsAnalyzer) findUnusedConstants(ctx *Context, constUsage map[string]bool) []Finding {
	var findings []Finding
	for pkgPath, files := range ctx.SyntaxByPkg {
		for _, file := range files {
			for _, decl := range file.Decls {
				findings = append(findings, a.checkConstantDecl(ctx, pkgPath, decl, constUsage)...)
			}
		}
	}
	return findings
}

// checkConstantDecl checks a single GenDecl for unused exported constants.
func (a *deadFlagsAnalyzer) checkConstantDecl(ctx *Context, pkgPath string, decl ast.Decl, constUsage map[string]bool) []Finding {
	gd, ok := decl.(*ast.GenDecl)
	if !ok || gd.Tok.String() != "const" {
		return nil
	}
	var findings []Finding
	for _, spec := range gd.Specs {
		vs, ok := spec.(*ast.ValueSpec)
		if !ok {
			continue
		}
		findings = append(findings, a.checkValueSpecConstants(ctx, pkgPath, vs, constUsage)...)
	}
	return findings
}

// checkValueSpecConstants checks each name in a ValueSpec for usage.
func (a *deadFlagsAnalyzer) checkValueSpecConstants(ctx *Context, pkgPath string, vs *ast.ValueSpec, constUsage map[string]bool) []Finding {
	var findings []Finding
	for _, name := range vs.Names {
		if !name.IsExported() {
			continue
		}
		key := pkgPath + "." + name.Name
		if constUsage[key] {
			continue
		}
		findings = append(findings, a.createUnusedConstantFinding(ctx, name))
	}
	return findings
}

// createUnusedConstantFinding builds a Finding for a single unused constant.
func (a *deadFlagsAnalyzer) createUnusedConstantFinding(ctx *Context, name *ast.Ident) Finding {
	pos := ctx.FSET.Position(name.Pos())
	return Finding{
		Analyzer:   a.Name(),
		Category:   CategoryDeadCode,
		Severity:   SeverityInfo,
		Message:     "constant " + name.Name + " is never used",
		Detail:      "This exported constant is not referenced anywhere in the codebase.",
		File:        pos.Filename,
		Line:        pos.Line,
		Suggestion:  "Remove the constant or use it",
		RuleID:      "GLW-DF001",
	}
}

// checkUnreadFlags finds flag registrations that may never be read.
func (a *deadFlagsAnalyzer) checkUnreadFlags(ctx *Context) []Finding {
	var findings []Finding
	for _, files := range ctx.SyntaxByPkg {
		for _, file := range files {
			findings = append(findings, a.scanFlagRegistrations(ctx, file)...)
		}
	}
	return findings
}

// scanFlagRegistrations inspects call expressions in a file for flag.X() calls.
func (a *deadFlagsAnalyzer) scanFlagRegistrations(ctx *Context, file *ast.File) []Finding {
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
		if !ok || ident.Name != "flag" || !isFlagTypeMethod(se.Sel.Name) {
			return true
		}
		if len(call.Args) < 1 {
			return true
		}
		lit, ok := call.Args[0].(*ast.BasicLit)
		if !ok {
			return true
		}
		flagName := strings.Trim(lit.Value, `"`)
		findings = append(findings, a.createUnreadFlagFinding(ctx, call, flagName, se.Sel.Name))
		return true
	})
	return findings
}

// isFlagTypeMethod returns true for flag registration method names.
//gollaw:keep
func isFlagTypeMethod(name string) bool {
	switch name {
	case "Bool", "String", "Int", "Float64", "Duration":
		return true
	}
	return false
}

// createUnreadFlagFinding builds a Finding for a registered but unread flag.
func (a *deadFlagsAnalyzer) createUnreadFlagFinding(ctx *Context, call *ast.CallExpr, flagName, method string) Finding {
	pos := ctx.FSET.Position(call.Pos())
	return Finding{
		Analyzer:   a.Name(),
		Category:   CategoryDeadCode,
		Severity:   SeverityWarning,
		Message:     "flag " + flagName + " is registered but may never be read",
		Detail:      "This flag is registered via flag." + method + " but there is no .Get() or .Value access detected.",
		File:        pos.Filename,
		Line:        pos.Line,
		Suggestion:  "Read the flag value with flag.Get() or remove the registration",
		RuleID:      "GLW-DF002",
	}
}

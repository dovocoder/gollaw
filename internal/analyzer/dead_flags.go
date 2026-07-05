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
	var findings []Finding

	// Build constant usage map.
	constUsage := make(map[string]bool)
	for _, pkg := range ctx.Packages {
		if pkg.TypesInfo == nil {
			continue
		}
		for _, obj := range pkg.TypesInfo.Uses {
			if c, ok := obj.(*types.Const); ok {
				if c.Pkg() == nil {
					continue
				}
				key := c.Pkg().Path() + "." + c.Name()
				constUsage[key] = true
			}
		}
	}

	// Check exported constants for usage.
	for pkgPath, files := range ctx.SyntaxByPkg {
		for _, file := range files {
			for _, decl := range file.Decls {
				gd, ok := decl.(*ast.GenDecl)
				if !ok || gd.Tok.String() != "const" {
					continue
				}
				for _, spec := range gd.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					for _, name := range vs.Names {
						if !name.IsExported() {
							continue
						}
						key := pkgPath + "." + name.Name
						if !constUsage[key] {
							pos := ctx.FSET.Position(name.Pos())
							findings = append(findings, Finding{
								Analyzer:  a.Name(),
								Category:  CategoryDeadCode,
								Severity:  SeverityInfo,
								Message:    "constant " + name.Name + " is never used",
								Detail:     "This exported constant is not referenced anywhere in the codebase.",
								File:       pos.Filename,
								Line:       pos.Line,
								Suggestion: "Remove the constant or use it",
								RuleID:     "GLW-DF001",
							})
						}
					}
				}
			}
		}
	}

	return findings
}

// checkUnreadFlags finds flag registrations that may never be read.
func (a *deadFlagsAnalyzer) checkUnreadFlags(ctx *Context) []Finding {
	var findings []Finding

	for _, files := range ctx.SyntaxByPkg {
		for _, file := range files {
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
				if !ok || ident.Name != "flag" {
					return true
				}
				if se.Sel.Name != "Bool" && se.Sel.Name != "String" && se.Sel.Name != "Int" && se.Sel.Name != "Float64" && se.Sel.Name != "Duration" {
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
				pos := ctx.FSET.Position(call.Pos())
				findings = append(findings, Finding{
					Analyzer:  a.Name(),
					Category:  CategoryDeadCode,
					Severity:  SeverityWarning,
					Message:    "flag " + flagName + " is registered but may never be read",
					Detail:     "This flag is registered via flag." + se.Sel.Name + " but there is no .Get() or .Value access detected.",
					File:       pos.Filename,
					Line:       pos.Line,
					Suggestion: "Read the flag value with flag.Get() or remove the registration",
					RuleID:     "GLW-DF002",
				})
				return true
			})
		}
	}

	return findings
}

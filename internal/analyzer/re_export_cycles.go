package analyzer

import (
	"go/ast"
	"strings"
)

// reExportCyclesAnalyzer detects re-export cycles between packages.
type reExportCyclesAnalyzer struct{}

func newReExportCyclesAnalyzer() *reExportCyclesAnalyzer { return &reExportCyclesAnalyzer{} }

func (a *reExportCyclesAnalyzer) Name() string        { return "re-export-cycles" }
func (a *reExportCyclesAnalyzer) Category() Category   { return categoryDependencies }
func (a *reExportCyclesAnalyzer) Description() string  { return "Detects re-export cycles between packages" }

func (a *reExportCyclesAnalyzer) Analyze(ctx *Context) ([]Finding, error) {
	var findings []Finding

	reExports := make(map[string]map[string]int)

	for pkgPath, files := range ctx.SyntaxByPkg {
		for _, file := range files {
			for _, decl := range file.Decls {
				if gd, ok := decl.(*ast.GenDecl); ok {
					for _, spec := range gd.Specs {
						if ts, ok := spec.(*ast.TypeSpec); ok {
							if ts.Assign != 0 {
								if ident, ok := ts.Type.(*ast.Ident); ok {
									reExportedFrom := findImportForIdent(file, ident.Name)
									if reExportedFrom != "" {
										if reExports[pkgPath] == nil {
											reExports[pkgPath] = make(map[string]int)
										}
										reExports[pkgPath][reExportedFrom]++
									}
								}
							}
						}
					}
				}
			}
		}
	}

	visited := make(map[string]bool)
	recStack := make(map[string]bool)

	var dfs func(pkg string, path []string) []string
	dfs = func(pkg string, path []string) []string {
		visited[pkg] = true
		recStack[pkg] = true
		path = append(path, pkg)
		for target := range reExports[pkg] {
			if !visited[target] {
				if cycle := dfs(target, path); cycle != nil {
					return cycle
				}
			} else if recStack[target] {
				return append(path, target)
			}
		}
		recStack[pkg] = false
		return nil
	}

	for pkgPath := range reExports {
		visited = make(map[string]bool)
		recStack = make(map[string]bool)
		if cycle := dfs(pkgPath, nil); cycle != nil {
			findings = append(findings, Finding{
				Analyzer:  a.Name(),
				Category:  categoryDependencies,
				Severity:  SeverityWarning,
				Message:    "re-export cycle: " + strings.Join(cycle, " → "),
				Detail:     "These packages re-export types from each other in a cycle, creating tight coupling.",
				File:       pkgPath,
				Line:       1,
				Suggestion: "Break the cycle by moving shared types to a common package",
				RuleID:     "GLW-RC001",
			})
		}
	}

	return findings, nil
}

func findImportForIdent(file *ast.File, identName string) string {
	for _, imp := range file.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		parts := strings.Split(path, "/")
		pkgName := parts[len(parts)-1]
		if imp.Name != nil {
			if imp.Name.Name == identName {
				return path
			}
		}
		if pkgName == identName {
			return path
		}
	}
	return ""
}

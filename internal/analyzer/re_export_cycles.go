package analyzer

import (
	"go/ast"
	"strings"
)

// reExportCyclesAnalyzer detects re-export cycles between packages.
type reExportCyclesAnalyzer struct{}

func newReExportCyclesAnalyzer() *reExportCyclesAnalyzer { return &reExportCyclesAnalyzer{} }

func (a *reExportCyclesAnalyzer) Name() string       { return "re-export-cycles" }
func (a *reExportCyclesAnalyzer) Category() Category { return categoryDependencies }
func (a *reExportCyclesAnalyzer) Description() string {
	return "Detects re-export cycles between packages"
}

func (a *reExportCyclesAnalyzer) Analyze(ctx *Context) ([]Finding, error) {
	reExports := a.collectReExports(ctx)
	return a.detectReExportCycles(reExports), nil
}

// collectReExports builds a map of pkgPath → {reExportedFromPkg → count}.
func (a *reExportCyclesAnalyzer) collectReExports(ctx *Context) map[string]map[string]int {
	reExports := make(map[string]map[string]int)
	for pkgPath, files := range ctx.SyntaxByPkg {
		for _, file := range files {
			a.collectFileReExports(file, pkgPath, reExports)
		}
	}
	return reExports
}

// collectFileReExports scans a single file for re-exported type aliases.
func (a *reExportCyclesAnalyzer) collectFileReExports(file *ast.File, pkgPath string, reExports map[string]map[string]int) {
	for _, decl := range file.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range gd.Specs {
			ts, ok := spec.(*ast.TypeSpec)
			if !ok || ts.Assign == 0 {
				continue
			}
			ident, ok := ts.Type.(*ast.Ident)
			if !ok {
				continue
			}
			reExportedFrom := findImportForIdent(file, ident.Name)
			if reExportedFrom == "" {
				continue
			}
			if reExports[pkgPath] == nil {
				reExports[pkgPath] = make(map[string]int)
			}
			reExports[pkgPath][reExportedFrom]++
		}
	}
}

// detectReExportCycles runs DFS on the re-export graph to find cycles.
func (a *reExportCyclesAnalyzer) detectReExportCycles(reExports map[string]map[string]int) []Finding {
	var findings []Finding
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
			findings = append(findings, createReExportCycleFinding(cycle))
		}
	}
	return findings
}

// createReExportCycleFinding builds a Finding for a detected re-export cycle.
func createReExportCycleFinding(cycle []string) Finding {
	return Finding{
		Analyzer:   "re-export-cycles",
		Category:   categoryDependencies,
		Severity:   SeverityWarning,
		Message:    "re-export cycle: " + strings.Join(cycle, " → "),
		Detail:     "These packages re-export types from each other in a cycle, creating tight coupling.",
		File:       cycle[0],
		Line:       1,
		Suggestion: "Agent fix: break the re-export cycle by moving shared types to a neutral package and importing that package directly from both sides.",
		RuleID:     "GLW-RC001",
	}
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

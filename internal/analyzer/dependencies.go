package analyzer

import (
	"fmt"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"
)

// dependencyAnalyzer builds the import graph and detects cycles.
type dependencyAnalyzer struct{}

func newDependencyAnalyzer() *dependencyAnalyzer { return &dependencyAnalyzer{} }

func (a *dependencyAnalyzer) Name() string        { return "dependencies" }
func (a *dependencyAnalyzer) Category() Category  { return CategoryDependencies }
func (a *dependencyAnalyzer) Description() string { return "Import graph cycles and dependency hygiene" }

func (a *dependencyAnalyzer) Analyze(ctx *Context) ([]Finding, error) {
	// Build adjacency list: pkg → set of imported pkg paths (only within our codebase).
	adj := make(map[string][]string)
	pkgSet := make(map[string]bool)
	for _, pkg := range ctx.Packages {
		pkgSet[pkg.PkgPath] = true
	}
	for _, pkg := range ctx.Packages {
		for _, imported := range pkg.Imports {
			if imported == nil {
				continue
			}
			if pkgSet[imported.PkgPath] {
				adj[pkg.PkgPath] = append(adj[pkg.PkgPath], imported.PkgPath)
			}
		}
	}

	// Detect cycles using DFS with a recursion stack.
	var findings []Finding
	cycles := detectCycles(adj)

	// Dedup cycles (same cycle can be found from different starting points).
	seenCycle := make(map[string]bool)
	for _, cycle := range cycles {
		// Normalize: find the lexicographically smallest node, rotate.
		key := normalizeCycle(cycle)
		if seenCycle[key] {
			continue
		}
		seenCycle[key] = true

		findings = append(findings, Finding{
			Analyzer:  a.Name(),
			Category:  a.Category(),
			Severity:  SeverityCritical,
			Message:    fmt.Sprintf("import cycle: %s", strings.Join(cycle, " → ")),
			Detail:     fmt.Sprintf("cycle length: %d packages", len(cycle)),
			File:       pkgFile(ctx, cycle[0]),
			Line:       1,
			RuleID:     "GLW-DE001",
			Suggestion: "Break the cycle by extracting shared code into a lower-level package, or using interfaces to invert the dependency.",
		})
	}

	// Check for dependency depth — packages that import too many others.
	for pkgPath, deps := range adj {
		if len(deps) > 20 {
			findings = append(findings, Finding{
				Analyzer:  a.Name(),
				Category:  a.Category(),
				Severity:  SeverityWarning,
				Message:    fmt.Sprintf("package %s imports %d internal packages", pkgPath, len(deps)),
				File:       pkgFile(ctx, pkgPath),
				Line:       1,
				RuleID:     "GLW-DE002",
				Suggestion: "High fan-out may indicate this package has too many responsibilities. Consider splitting it.",
			})
		}
	}

	sort.Slice(findings, func(i, j int) bool {
		return findings[i].File < findings[j].File
	})

	return findings, nil
}

// detectCycles finds all simple cycles in the directed graph using DFS.
func detectCycles(adj map[string][]string) [][]string {
	var cycles [][]string
	visited := make(map[string]bool)
	stack := make(map[string]bool)
	var path []string

	var dfs func(node string)
	dfs = func(node string) {
		visited[node] = true
		stack[node] = true
		path = append(path, node)

		for _, neighbor := range adj[node] {
			if !visited[neighbor] {
				dfs(neighbor)
			} else if stack[neighbor] {
				// Found a cycle — extract it.
				cycleStart := 0
				for i, n := range path {
					if n == neighbor {
						cycleStart = i
						break
					}
				}
				cycle := make([]string, len(path)-cycleStart)
				copy(cycle, path[cycleStart:])
				cycle = append(cycle, neighbor) // close the cycle
				cycles = append(cycles, cycle)
			}
		}

		path = path[:len(path)-1]
		stack[node] = false
	}

	// Sort nodes for deterministic traversal.
	nodes := make([]string, 0, len(adj))
	for n := range adj {
		nodes = append(nodes, n)
	}
	sort.Strings(nodes)

	for _, n := range nodes {
		if !visited[n] {
			dfs(n)
		}
	}

	return cycles
}

func normalizeCycle(cycle []string) string {
	if len(cycle) == 0 {
		return ""
	}
	// Remove the closing node (last == first).
	if len(cycle) > 1 && cycle[0] == cycle[len(cycle)-1] {
		cycle = cycle[:len(cycle)-1]
	}
	// Find smallest element, rotate.
	minIdx := 0
	for i, n := range cycle {
		if n < cycle[minIdx] {
			minIdx = i
		}
	}
	rotated := append(cycle[minIdx:], cycle[:minIdx]...)
	return strings.Join(rotated, "→")
}

func pkgFile(ctx *Context, pkgPath string) string {
	for _, pkg := range ctx.Packages {
		if pkg.PkgPath == pkgPath && len(pkg.GoFiles) > 0 {
			return pkg.GoFiles[0]
		}
	}
	return pkgPath
}

var _ = packages.Load

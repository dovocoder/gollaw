package graph

import (
	"path/filepath"
	"sort"
	"strings"
)

// closureResult holds the output of transitive impact analysis on changed files.
type closureResult struct {
	// InDiff are changed files that are part of the diff/PR.
	InDiff []string
	// AffectedNotShown are files transitively affected but not in the diff.
	AffectedNotShown []string
	// coordinationGaps are cases where a changed package exports symbols
	// consumed by a package NOT in the diff — a coordination risk.
	coordinationGaps []coordinationGap
}

// coordinationGap represents a single coordination risk between a changed
// file and a consumer file that is not part of the diff.
type coordinationGap struct {
	ChangedFile      string
	ConsumerFile     string
	ConsumedSymbols   []string
}

// impactClosure computes the transitive impact of changedFiles on the graph.
//
// It maps changed files to their containing packages, walks reverse
// dependencies transitively (who imports the changed packages), and
// partitions the reached files into those already in the diff and those
// affected but not shown. Coordination gaps surface exported symbols from
// changed packages that are consumed by packages outside the diff.
func impactClosure(graph *ModuleGraph, changedFiles []string) *closureResult {
	result := &closureResult{
		InDiff:           changedFiles,
	}

	if graph == nil || len(changedFiles) == 0 {
		return result
	}

	// Build a set of changed file basenames for membership tests.
	changedSet := make(map[string]bool, len(changedFiles))
	for _, f := range changedFiles {
		changedSet[filepath.Base(f)] = true
		changedSet[f] = true
	}

	// Map changed files → package paths.
	changedPkgs := changedFileToPackages(graph, changedFiles)
	if len(changedPkgs) == 0 {
		return result
	}

	// Transitively walk reverse deps (who imports changed packages).
	affected := computeAffected(graph, changedPkgs)

	// Partition reached files: those in the diff vs affected but not shown.
	for pkgPath := range affected {
		pkgID := graph.NodeByPath(pkgPath)
		if pkgID < 0 {
			continue
		}
		for _, f := range graph.Nodes[pkgID].Files {
			base := filepath.Base(f)
			if changedSet[base] || changedSet[f] {
				continue // already in diff
			}
			result.AffectedNotShown = append(result.AffectedNotShown, f)
		}
	}
	sort.Strings(result.AffectedNotShown)

	// Find coordination gaps.
	result.coordinationGaps = findCoordinationGaps(graph, changedPkgs, changedSet)

	return result
}

// computeAffected transitively walks reverse dependencies to find all
// packages affected by changes to changedPkgs.
func computeAffected(graph *ModuleGraph, changedPkgs map[string]bool) map[string]bool {
	affected := make(map[string]bool)
	visited := make(map[string]bool)
	queue := make([]string, 0, len(changedPkgs))
	for pkg := range changedPkgs {
		queue = append(queue, pkg)
		visited[pkg] = true
	}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		for _, importerID := range graph.ReverseDeps(current) {
			importerPath := graph.Nodes[importerID].Path
			if visited[importerPath] {
				continue
			}
			visited[importerPath] = true
			affected[importerPath] = true
			queue = append(queue, importerPath)
		}
	}
	return affected
}

// findCoordinationGaps finds cases where a changed package exports symbols
// consumed by a package NOT in the diff.
func findCoordinationGaps(graph *ModuleGraph, changedPkgs, changedSet map[string]bool) []coordinationGap {
	_ = changedSet // reserved for file-level diff checks
	var gaps []coordinationGap
	for changedPkg := range changedPkgs {
		changedID := graph.NodeByPath(changedPkg)
		if changedID < 0 {
			continue
		}
		for _, edge := range graph.Edges {
			if edge.Target != changedID {
				continue
			}
			// edge.Source imports changed package.
			consumerPkg := graph.Nodes[edge.Source].Path
			if changedPkgs[consumerPkg] {
				continue // consumer is also in the diff — not a gap
			}
			changedFile := ""
			if len(graph.Nodes[changedID].Files) > 0 {
				changedFile = graph.Nodes[changedID].Files[0]
			}
			consumerFile := ""
			if len(graph.Nodes[edge.Source].Files) > 0 {
				consumerFile = graph.Nodes[edge.Source].Files[0]
			}
			symbols := edge.Imports
			if len(symbols) == 0 {
				symbols = []string{"*"}
			}
			gaps = append(gaps, coordinationGap{
				ChangedFile:     changedFile,
				ConsumerFile:    consumerFile,
				ConsumedSymbols:  append([]string(nil), symbols...),
			})
		}
	}
	return gaps
}

// changedFileToPackages maps changed file paths to package paths in the graph.
func changedFileToPackages(graph *ModuleGraph, changedFiles []string) map[string]bool {
	result := make(map[string]bool)
	for _, changed := range changedFiles {
		base := filepath.Base(changed)
		for i, node := range graph.Nodes {
			for _, f := range node.Files {
				if f == changed || filepath.Base(f) == base ||
					strings.HasSuffix(f, "/"+base) {
					result[node.Path] = true
					_ = i
					break
				}
			}
		}
	}
	return result
}

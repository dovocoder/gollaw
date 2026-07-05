package graph

import "sort"

// ReachabilityResult holds the output of BFS reachability analysis.
type ReachabilityResult struct {
	Reachable   []string
	Unreachable []string
	EntryPoints []string
}

// ComputeReachability performs a BFS from the given entry points through
// forward edges (imports) to determine which packages are reachable.
//
// Packages not reachable from any entry point are flagged as unreachable —
// these are candidates for dead code elimination.
//
// Entry points typically include main packages, packages with exported
// symbols used by external importers, and test packages.
func ComputeReachability(graph *ModuleGraph, entryPoints []string) *ReachabilityResult {
	result := &ReachabilityResult{
		EntryPoints: append([]string(nil), entryPoints...),
	}
	if graph == nil || len(graph.Nodes) == 0 {
		return result
	}

	// If no entry points provided, use packages marked as entry points.
	if len(entryPoints) == 0 {
		for _, node := range graph.Nodes {
			if node.IsEntryPoint {
				entryPoints = append(entryPoints, node.Path)
			}
		}
	}

	// BFS through forward edges.
	visited := make(map[string]bool)
	queue := make([]string, 0, len(entryPoints))
	for _, ep := range entryPoints {
		if graph.NodeByPath(ep) >= 0 {
			visited[ep] = true
			queue = append(queue, ep)
		}
	}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		for _, depID := range graph.ForwardDeps(current) {
			depPath := graph.Nodes[depID].Path
			if visited[depPath] {
				continue
			}
			visited[depPath] = true
			queue = append(queue, depPath)
		}
	}

	// Partition into reachable / unreachable.
	for _, node := range graph.Nodes {
		if visited[node.Path] {
			result.Reachable = append(result.Reachable, node.Path)
		} else {
			result.Unreachable = append(result.Unreachable, node.Path)
		}
	}
	sort.Strings(result.Reachable)
	sort.Strings(result.Unreachable)

	return result
}

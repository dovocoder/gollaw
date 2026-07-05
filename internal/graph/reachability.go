package graph

import "sort"

// reachabilityResult holds the output of BFS reachability analysis.
type reachabilityResult struct {
	Reachable   []string
	Unreachable []string
	EntryPoints []string
}

// computeReachability performs a BFS from the given entry points through
// forward edges (imports) to determine which packages are reachable.
//
// Packages not reachable from any entry point are flagged as unreachable —
// these are candidates for dead code elimination.
//
// Entry points typically include main packages, packages with exported
// symbols used by external importers, and test packages.
//gollaw:keep
func computeReachability(graph *ModuleGraph, entryPoints []string) *reachabilityResult {
	result := &reachabilityResult{
		EntryPoints: append([]string(nil), entryPoints...),
	}
	if graph == nil || len(graph.Nodes) == 0 {
		return result
	}

	eps := resolveEntryPoints(graph, entryPoints)
	visited := bfsForward(graph, eps)
	partitionReachable(graph, visited, result)
	return result
}

// resolveEntryPoints returns entry points, defaulting to packages marked
// as entry points when none are explicitly provided.
func resolveEntryPoints(graph *ModuleGraph, entryPoints []string) []string {
	if len(entryPoints) > 0 {
		return entryPoints
	}
	for _, node := range graph.Nodes {
		if node.IsEntryPoint {
			entryPoints = append(entryPoints, node.Path)
		}
	}
	return entryPoints
}

// bfsForward performs a BFS through forward edges from the given entry points,
// returning the set of visited package paths.
func bfsForward(graph *ModuleGraph, entryPoints []string) map[string]bool {
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
	return visited
}

// partitionReachable splits nodes into reachable and unreachable slices
// based on the visited set, then sorts both.
func partitionReachable(graph *ModuleGraph, visited map[string]bool, result *reachabilityResult) {
	for _, node := range graph.Nodes {
		if visited[node.Path] {
			result.Reachable = append(result.Reachable, node.Path)
		} else {
			result.Unreachable = append(result.Unreachable, node.Path)
		}
	}
	sort.Strings(result.Reachable)
	sort.Strings(result.Unreachable)
}

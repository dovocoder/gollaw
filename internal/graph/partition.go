package graph

import "sort"

// PartitionOrder returns layers of packages in topological order.
// Layer 0 contains packages with no dependencies on other graph packages.
// Layer N contains packages that depend on packages in layer N-1 or earlier.
//
// This is useful for build ordering, understanding dependency depth, and
// identifying circular dependency violations.
func PartitionOrder(graph *ModuleGraph) [][]string {
	if graph == nil || len(graph.Nodes) == 0 {
		return nil
	}

	n := len(graph.Nodes)
	layer := make([]int, n)
	for i := range layer {
		layer[i] = -1
	}

	// Compute in-degree for each node (count of edges targeting it from within graph).
	inDegree := make([]int, n)
	for _, edge := range graph.Edges {
		inDegree[edge.Target]++
	}

	// Kahn's algorithm with layering.
	currentLayer := 0
	queue := make([]int, 0)
	for i := 0; i < n; i++ {
		if inDegree[i] == 0 {
			queue = append(queue, i)
			layer[i] = 0
		}
	}

	processed := 0
	for len(queue) > 0 {
		nextQueue := make([]int, 0)
		for _, node := range queue {
			processed++
			nodePath := graph.Nodes[node].Path
			for _, depID := range graph.ForwardDeps(nodePath) {
				inDegree[depID]--
				if inDegree[depID] == 0 {
					layer[depID] = currentLayer + 1
					nextQueue = append(nextQueue, depID)
				}
			}
		}
		queue = nextQueue
		currentLayer++
	}

	// If processed < n, there are cycles — remaining nodes get the max layer.
	if processed < n {
		for i := 0; i < n; i++ {
			if layer[i] == -1 {
				layer[i] = currentLayer
			}
		}
	}

	// Group by layer.
	numLayers := currentLayer + 1
	layers := make([][]string, numLayers)
	for i, node := range graph.Nodes {
		l := layer[i]
		if l >= 0 && l < numLayers {
			layers[l] = append(layers[l], node.Path)
		}
	}
	// Remove empty trailing layers.
	for len(layers) > 0 && len(layers[len(layers)-1]) == 0 {
		layers = layers[:len(layers)-1]
	}
	// Sort within each layer for deterministic output.
	for i := range layers {
		sort.Strings(layers[i])
	}
	return layers
}

// DetectCircularDeps finds all cycles in the graph using DFS.
// Each returned slice is one cycle represented as a list of package paths.
func DetectCircularDeps(graph *ModuleGraph) [][]string {
	if graph == nil || len(graph.Nodes) == 0 {
		return nil
	}

	n := len(graph.Nodes)
	color := make([]byte, n) // 0=white, 1=gray, 2=black
	stack := make([]int, 0)
	var cycles [][]string

	var dfs func(u int)
	dfs = func(u int) {
		color[u] = 1 // gray
		stack = append(stack, u)
		for _, v := range graph.ForwardDeps(graph.Nodes[u].Path) {
			switch color[v] {
			case 0: // white — not yet visited
				dfs(v)
			case 1: // gray — back edge → cycle
				// Extract cycle from stack starting at node v.
				for i := len(stack) - 1; i >= 0; i-- {
					if stack[i] == v {
						cycle := make([]string, 0, len(stack)-i)
						for j := i; j < len(stack); j++ {
							cycle = append(cycle, graph.Nodes[stack[j]].Path)
						}
						cycles = append(cycles, cycle)
						break
					}
				}
			}
		}
		stack = stack[:len(stack)-1]
		color[u] = 2 // black
	}

	for i := 0; i < n; i++ {
		if color[i] == 0 {
			dfs(i)
		}
	}

	return deduplicateCycles(cycles)
}

// deduplicateCycles removes duplicate cycles (same set of nodes, different rotation).
func deduplicateCycles(cycles [][]string) [][]string {
	seen := make(map[string]bool)
	var result [][]string
	for _, cycle := range cycles {
		key := cycleKey(cycle)
		if !seen[key] {
			seen[key] = true
			result = append(result, cycle)
		}
	}
	return result
}

// cycleKey produces a canonical key for a cycle, independent of starting node.
func cycleKey(cycle []string) string {
	if len(cycle) == 0 {
		return ""
	}
	// Find the lexicographically smallest element as the canonical start.
	minIdx := 0
	for i := 1; i < len(cycle); i++ {
		if cycle[i] < cycle[minIdx] {
			minIdx = i
		}
	}
	key := ""
	for i := 0; i < len(cycle); i++ {
		idx := (minIdx + i) % len(cycle)
		key += cycle[idx] + "|"
	}
	return key
}

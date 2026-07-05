package graph

import "sort"

// partitionOrder returns layers of packages in topological order.
// Layer 0 contains packages with no dependencies on other graph packages.
// Layer N contains packages that depend on packages in layer N-1 or earlier.
//
// This is useful for build ordering, understanding dependency depth, and
// identifying circular dependency violations.
func partitionOrder(graph *ModuleGraph) [][]string {
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

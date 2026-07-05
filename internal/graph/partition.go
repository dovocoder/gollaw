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

	inDegree := computeInDegree(graph)
	currentLayer, processed := runKahnLayering(graph, inDegree, layer, n)
	assignCycleLayers(layer, currentLayer, processed, n)
	layers := groupNodesByLayer(graph, layer, currentLayer)
	return layers
}

// computeInDegree counts edges targeting each node from within the graph.
func computeInDegree(graph *ModuleGraph) []int {
	inDegree := make([]int, len(graph.Nodes))
	for _, edge := range graph.Edges {
		inDegree[edge.Target]++
	}
	return inDegree
}

// runKahnLayering executes Kahn's algorithm with layering, returning the
// final layer count and the number of processed nodes.
func runKahnLayering(graph *ModuleGraph, inDegree []int, layer []int, n int) (int, int) {
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
			processNodeDeps(graph, node, inDegree, layer, currentLayer, &nextQueue)
		}
		queue = nextQueue
		currentLayer++
	}
	return currentLayer, processed
}

// processNodeDeps decrements in-degree for dependents and queues ready nodes.
func processNodeDeps(graph *ModuleGraph, node int, inDegree, layer []int, currentLayer int, nextQueue *[]int) {
	nodePath := graph.Nodes[node].Path
	for _, depID := range graph.ForwardDeps(nodePath) {
		inDegree[depID]--
		if inDegree[depID] == 0 {
			layer[depID] = currentLayer + 1
			*nextQueue = append(*nextQueue, depID)
		}
	}
}

// assignCycleLayers assigns remaining unprocessed nodes (in cycles) to max layer.
func assignCycleLayers(layer []int, currentLayer, processed, n int) {
	if processed >= n {
		return
	}
	for i := 0; i < n; i++ {
		if layer[i] == -1 {
			layer[i] = currentLayer
		}
	}
}

// groupNodesByLayer groups node paths by their layer index, sorts each layer,
// and trims empty trailing layers.
func groupNodesByLayer(graph *ModuleGraph, layer []int, currentLayer int) [][]string {
	numLayers := currentLayer + 1
	layers := make([][]string, numLayers)
	for i, node := range graph.Nodes {
		l := layer[i]
		if l >= 0 && l < numLayers {
			layers[l] = append(layers[l], node.Path)
		}
	}
	for len(layers) > 0 && len(layers[len(layers)-1]) == 0 {
		layers = layers[:len(layers)-1]
	}
	for i := range layers {
		sort.Strings(layers[i])
	}
	return layers
}

// Package trace provides symbol-level call-chain tracing: "who calls X,
// transitively" and "what does X call".
package trace

import (
	"fmt"
	"strings"

	"github.com/dovocoder/gollaw/internal/analyzer"
	"github.com/dovocoder/gollaw/internal/ssalookup"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/callgraph/static"
	"golang.org/x/tools/go/ssa"
)

const defaultMaxDepth = 10

// TraceResult holds the result of a call-chain trace.
type TraceResult struct {
	Symbol     string        `json:"symbol"`
	Direction  string        `json:"direction"` // "callers" or "callees"
	Chains     [][]traceNode `json:"chains"`
	TotalPaths int           `json:"totalPaths"`
}

// traceNode is a single node in a call chain.
type traceNode struct {
	Function string `json:"function"`
	Location string `json:"location"` // file:line
	Package  string `json:"package"`
	Depth    int    `json:"depth"`
}

// traceState holds shared state for a DFS trace.
type traceState struct {
	maxDepth int
	visited  map[string]bool
	path     []traceNode
}

// TraceCallers finds all functions that call the given symbol, transitively,
// up to maxDepth levels. If maxDepth <= 0, defaultMaxDepth is used.
func TraceCallers(ctx *analyzer.Context, symbolName string, maxDepth int) (*TraceResult, error) {
	fn, err := resolveFunction(ctx, symbolName, maxDepth, &maxDepth)
	if err != nil {
		return nil, err
	}

	cg := static.CallGraph(ctx.SSA)
	reverseEdges := buildReverseEdges(cg)

	state := &traceState{maxDepth: maxDepth, visited: make(map[string]bool)}
	var chains [][]traceNode

	dfs := func(current *ssa.Function, depth int) {}
	dfs = func(current *ssa.Function, depth int) {
		key := current.String()
		if state.visited[key] || depth > state.maxDepth {
			return
		}
		state.visited[key] = true
		state.path = append(state.path, makeTraceNode(ctx, current, depth))

		callers := reverseEdges[current]
		if len(callers) == 0 || depth == maxDepth {
			if len(state.path) > 1 {
				chains = append(chains, reversePath(state.path))
			}
		} else {
			for _, caller := range callers {
				dfs(caller, depth+1)
			}
		}
		state.path = state.path[:len(state.path)-1]
		state.visited[key] = false
	}

	dfs(fn, 0)
	chains = ensureAtLeastOneChain(chains, ctx, fn)

	return &TraceResult{Symbol: symbolName, Direction: "callers", Chains: chains, TotalPaths: len(chains)}, nil
}

// TraceCallees finds all functions called by the given symbol, transitively,
// up to maxDepth levels. If maxDepth <= 0, defaultMaxDepth is used.
func TraceCallees(ctx *analyzer.Context, symbolName string, maxDepth int) (*TraceResult, error) {
	fn, err := resolveFunction(ctx, symbolName, maxDepth, &maxDepth)
	if err != nil {
		return nil, err
	}

	cg := static.CallGraph(ctx.SSA)
	state := &traceState{maxDepth: maxDepth, visited: make(map[string]bool)}
	var chains [][]traceNode

	dfs := func(current *ssa.Function, depth int) {}
	dfs = func(current *ssa.Function, depth int) {
		key := current.String()
		if state.visited[key] || depth > state.maxDepth {
			return
		}
		state.visited[key] = true
		state.path = append(state.path, makeTraceNode(ctx, current, depth))

		callees := getCallees(cg, current)
		if len(callees) == 0 || depth == maxDepth {
			if len(state.path) > 1 {
				chain := make([]traceNode, len(state.path))
				copy(chain, state.path)
				chains = append(chains, chain)
			}
		} else {
			for _, callee := range callees {
				dfs(callee, depth+1)
			}
		}
		state.path = state.path[:len(state.path)-1]
		state.visited[key] = false
	}

	dfs(fn, 0)
	chains = ensureAtLeastOneChain(chains, ctx, fn)

	return &TraceResult{Symbol: symbolName, Direction: "callees", Chains: chains, TotalPaths: len(chains)}, nil
}

// resolveFunction validates SSA, resolves maxDepth, and finds the function.
func resolveFunction(ctx *analyzer.Context, symbolName string, maxDepth int, maxDepthPtr *int) (*ssa.Function, error) {
	if ctx.SSA == nil {
		return nil, fmt.Errorf("SSA program not available")
	}
	if maxDepth <= 0 {
		*maxDepthPtr = defaultMaxDepth
	}
	fn := ssalookup.FindFunction(ctx, symbolName)
	if fn == nil {
		return nil, fmt.Errorf("function %q not found in the analyzed codebase", symbolName)
	}
	return fn, nil
}

// buildReverseEdges builds a map of callee → list of callers.
func buildReverseEdges(cg *callgraph.Graph) map[*ssa.Function][]*ssa.Function {
	reverseEdges := make(map[*ssa.Function][]*ssa.Function)
	for _, node := range cg.Nodes {
		if node == nil || node.Func == nil {
			continue
		}
		for _, edge := range node.Out {
			if edge.Callee != nil && edge.Callee.Func != nil {
				callee := edge.Callee.Func
				reverseEdges[callee] = append(reverseEdges[callee], node.Func)
			}
		}
	}
	return reverseEdges
}

// getCallees returns all callee functions for a given function in the call graph.
func getCallees(cg *callgraph.Graph, fn *ssa.Function) []*ssa.Function {
	node := cg.Nodes[fn]
	if node == nil {
		return nil
	}
	var callees []*ssa.Function
	for _, edge := range node.Out {
		if edge.Callee != nil && edge.Callee.Func != nil {
			callees = append(callees, edge.Callee.Func)
		}
	}
	return callees
}

// makeTraceNode creates a traceNode from an SSA function.
func makeTraceNode(ctx *analyzer.Context, fn *ssa.Function, depth int) traceNode {
	return traceNode{
		Function: ssalookup.CleanFuncName(fn),
		Location: ssalookup.FuncLocation(ctx, fn),
		Package:  ssalookup.FuncPackage(fn),
		Depth:    depth,
	}
}

// reversePath reverses a path slice (entry → ... → target).
func reversePath(path []traceNode) []traceNode {
	chain := make([]traceNode, len(path))
	for i, j := 0, len(path)-1; j >= 0; i, j = i+1, j-1 {
		chain[i] = path[j]
	}
	return chain
}

// ensureAtLeastOneChain returns chains, or a single-node chain if empty.
func ensureAtLeastOneChain(chains [][]traceNode, ctx *analyzer.Context, fn *ssa.Function) [][]traceNode {
	if len(chains) == 0 {
		return [][]traceNode{{makeTraceNode(ctx, fn, 0)}}
	}
	return chains
}

// FormatTraceText produces a tree-like text representation of the trace.
func FormatTraceText(result *TraceResult) string {
	var b strings.Builder

	dir := "CALLERS"
	if result.Direction == "callees" {
		dir = "CALLEES"
	}

	fmt.Fprintf(&b, "Trace: %s (%s)\n", result.Symbol, dir)
	fmt.Fprintf(&b, "────────────────────────────────────\n")
	fmt.Fprintf(&b, "Total paths: %d\n\n", result.TotalPaths)

	if len(result.Chains) == 0 {
		fmt.Fprintf(&b, "(no paths found)\n")
		return b.String()
	}

	writeChains(&b, result.Chains)
	return b.String()
}

// writeChains writes all chains to the builder.
func writeChains(b *strings.Builder, chains [][]traceNode) {
	for i, chain := range chains {
		fmt.Fprintf(b, "Path %d:\n", i+1)
		writeChainNodes(b, chain)
		fmt.Fprintf(b, "\n")
	}
}

// writeChainNodes writes the nodes of a single chain.
func writeChainNodes(b *strings.Builder, chain []traceNode) {
	for j, node := range chain {
		indent := strings.Repeat("  ", j)
		arrow := "→"
		if j == 0 {
			arrow = "◆"
		}
		if j == len(chain)-1 && j > 0 {
			arrow = "▸"
		}
		fmt.Fprintf(b, "%s%s %s  (%s)  [%s]\n", indent, arrow, node.Function, node.Location, node.Package)
	}
}

// Package explain traces why a symbol is unused or dead, showing the
// call chain that would (or wouldn't) reach it.
package explain

import (
	"fmt"
	"go/types"
	"sort"
	"strings"

	"github.com/dovocoder/gollaw/internal/analyzer"
	"github.com/dovocoder/gollaw/internal/ssalookup"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/callgraph/static"
	"golang.org/x/tools/go/ssa"
)

// Explanation describes the status of a symbol and why it is
// unused, dead, or used.
type Explanation struct {
	Symbol    string     `json:"symbol"`
	Kind      string     `json:"kind"`       // function, type, method
	Status    string     `json:"status"`     // unused, dead, used
	Location  string     `json:"location"`   // file:line
	CallChain []callNode `json:"callChain"`  // who calls it, transitively (entry → ... → target)
	Reason    string     `json:"reason"`
}

// callNode is a single node in a call chain.
type callNode struct {
	Function string `json:"function"`
	Location string `json:"location"` // file:line
	Package  string `json:"package"`
}

// ExplainUnused finds a symbol by name and explains why it is unused
// (never referenced outside its own package or never called at all).
func ExplainUnused(ctx *analyzer.Context, symbolName string) (*Explanation, error) {
	fn := ssalookup.FindFunction(ctx, symbolName)
	if fn != nil {
		return explainUnusedFunction(ctx, fn, symbolName)
	}
	obj := findTypeObject(ctx, symbolName)
	if obj != nil {
		return explainUnusedObject(ctx, obj, symbolName)
	}
	return nil, fmt.Errorf("symbol %q not found in the analyzed codebase", symbolName)
}

// ExplainDead finds a dead (unreachable) function by name and explains
// what would need to call it for it to become reachable.
func ExplainDead(ctx *analyzer.Context, symbolName string) (*Explanation, error) {
	fn := ssalookup.FindFunction(ctx, symbolName)
	if fn == nil {
		return nil, fmt.Errorf("function %q not found in the analyzed codebase", symbolName)
	}

	loc := ssalookup.FuncLocation(ctx, fn)
	expl := &Explanation{Symbol: symbolName, Kind: funcKind(fn), Location: loc}

	cg := static.CallGraph(ctx.SSA)
	if isReachable(cg, fn) {
		expl.Status = "used"
		expl.Reason = fmt.Sprintf("function %s is reachable from an entry point", ssalookup.CleanFuncName(fn))
		expl.CallChain = findCallChainFromEntry(ctx, cg, fn)
		return expl, nil
	}

	expl.Status = "dead"
	expl.Reason = fmt.Sprintf("function %s is not reachable from any entry point (main, init, exported, or method). No call chain reaches it.", ssalookup.CleanFuncName(fn))
	expl.CallChain = findPotentialCallers(ctx, cg, fn)
	return expl, nil
}

// FormatExplanation produces a human-readable explanation.
func FormatExplanation(e *Explanation) string {
	var b strings.Builder

	fmt.Fprintf(&b, "Explanation: %s\n", e.Symbol)
	fmt.Fprintf(&b, "────────────────────────────────────\n")
	fmt.Fprintf(&b, "  Kind:     %s\n", e.Kind)
	fmt.Fprintf(&b, "  Status:   %s\n", e.Status)
	fmt.Fprintf(&b, "  Location: %s\n", e.Location)
	fmt.Fprintf(&b, "\n")

	writeCallChain(&b, e)
	fmt.Fprintf(&b, "\nReason: %s\n", e.Reason)
	return b.String()
}

// writeCallChain writes the call chain section of an explanation.
func writeCallChain(b *strings.Builder, e *Explanation) {
	if len(e.CallChain) > 0 {
		fmt.Fprintf(b, "Call chain:\n")
		for i, node := range e.CallChain {
			if i == len(e.CallChain)-1 && e.Status != "dead" {
				fmt.Fprintf(b, "  → %s  (%s)  [%s]  ← target\n", node.Function, node.Location, node.Package)
			} else {
				fmt.Fprintf(b, "  → %s  (%s)  [%s]\n", node.Function, node.Location, node.Package)
			}
		}
	} else {
		fmt.Fprintf(b, "Call chain: (none found)\n")
	}
}

// ─── Internal helpers ────────────────────────────────────────────────

// findTypeObject searches for a non-function exported symbol (type, var, const).
func findTypeObject(ctx *analyzer.Context, name string) types.Object {
	for _, typPkg := range ctx.TypesByPkg {
		scope := typPkg.Scope()
		lookupName := name
		parts := strings.Split(name, ".")
		if len(parts) > 1 {
			lookupName = parts[len(parts)-1]
		}
		obj := scope.Lookup(lookupName)
		if obj != nil {
			return obj
		}
	}
	return nil
}

// explainUnusedFunction creates an explanation for an unused function.
func explainUnusedFunction(ctx *analyzer.Context, fn *ssa.Function, symbolName string) (*Explanation, error) {
	loc := ssalookup.FuncLocation(ctx, fn)
	expl := &Explanation{Symbol: symbolName, Kind: funcKind(fn), Location: loc}

	cg := static.CallGraph(ctx.SSA)
	if isReachable(cg, fn) {
		setReachableStatus(expl, ctx, cg, fn)
	} else {
		expl.Status = "dead"
		expl.Reason = fmt.Sprintf("function %s is not reachable from any entry point", ssalookup.CleanFuncName(fn))
		expl.CallChain = findPotentialCallers(ctx, cg, fn)
	}
	return expl, nil
}

// setReachableStatus sets the explanation for a reachable function.
func setReachableStatus(expl *Explanation, ctx *analyzer.Context, cg *callgraph.Graph, fn *ssa.Function) {
	externalCallers := findExternalCallers(ctx, cg, fn)
	if len(externalCallers) == 0 {
		expl.Status = "unused"
		expl.Reason = fmt.Sprintf("function %s is reachable but only within its own package; not called externally", ssalookup.CleanFuncName(fn))
	} else {
		expl.Status = "used"
		expl.Reason = fmt.Sprintf("function %s is reachable and called externally", ssalookup.CleanFuncName(fn))
	}
	expl.CallChain = findCallChainFromEntry(ctx, cg, fn)
}

// explainUnusedObject creates an explanation for an unused type/variable/constant.
func explainUnusedObject(ctx *analyzer.Context, obj types.Object, symbolName string) (*Explanation, error) {
	pos := ctx.FSET.Position(obj.Pos())
	expl := &Explanation{
		Symbol:   symbolName,
		Kind:     kindOf(obj),
		Location: fmt.Sprintf("%s:%d", pos.Filename, pos.Line),
	}

	usedExternally := isUsedExternally(ctx, obj)
	if usedExternally {
		expl.Status = "used"
		expl.Reason = fmt.Sprintf("%s %s is referenced outside its defining package", expl.Kind, symbolName)
	} else {
		expl.Status = "unused"
		expl.Reason = fmt.Sprintf("%s %s is not referenced outside its defining package", expl.Kind, symbolName)
	}
	return expl, nil
}

// isUsedExternally checks if obj is referenced outside its defining package.
func isUsedExternally(ctx *analyzer.Context, obj types.Object) bool {
	for _, pkg := range ctx.Packages {
		if pkg.TypesInfo == nil || pkg.PkgPath == obj.Pkg().Path() {
			continue
		}
		for _, usedObj := range pkg.TypesInfo.Uses {
			if usedObj == obj {
				return true
			}
		}
	}
	return false
}

// isReachable checks if the given function is reachable from any entry point
// in the call graph.
func isReachable(cg *callgraph.Graph, target *ssa.Function) bool {
	visited := make(map[*callgraph.Node]bool)
	queue := collectEntryPoints(cg)

	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		if visited[n] {
			continue
		}
		visited[n] = true
		if n.Func == target {
			return true
		}
		for _, edge := range n.Out {
			if edge.Callee != nil && !visited[edge.Callee] {
				queue = append(queue, edge.Callee)
			}
		}
	}
	return false
}

// collectEntryPoints returns initial BFS nodes: main, init, exported, methods.
func collectEntryPoints(cg *callgraph.Graph) []*callgraph.Node {
	visited := make(map[*callgraph.Node]bool)
	var queue []*callgraph.Node
	add := func(n *callgraph.Node) {
		if n != nil && !visited[n] {
			visited[n] = true
			queue = append(queue, n)
		}
	}
	for _, n := range cg.Nodes {
		if n == nil || n.Func == nil {
			continue
		}
		fn := n.Func
		if fn.Name() == "main" || fn.Name() == "init" {
			add(n)
		}
		if fn.Object() != nil && fn.Object().Exported() {
			add(n)
		}
		if fn.Signature != nil && fn.Signature.Recv() != nil {
			add(n)
		}
	}
	return queue
}

// findCallChainFromEntry performs a BFS from entry points to the target,
// returning the call chain (entry → ... → target).
func findCallChainFromEntry(ctx *analyzer.Context, cg *callgraph.Graph, target *ssa.Function) []callNode {
	parent := make(map[*ssa.Function]*ssa.Function)
	visited := make(map[*ssa.Function]bool)
	var queue []*ssa.Function

	addEntry := func(fn *ssa.Function) {
		if fn != nil && !visited[fn] {
			visited[fn] = true
			queue = append(queue, fn)
		}
	}

	for _, n := range cg.Nodes {
		if n == nil || n.Func == nil {
			continue
		}
		fn := n.Func
		if fn.Name() == "main" || fn.Name() == "init" {
			addEntry(fn)
		}
		if fn.Object() != nil && fn.Object().Exported() {
			addEntry(fn)
		}
	}

	chain := bfsToTarget(cg, queue, visited, parent, target)
	if chain == nil {
		return nil
	}
	return functionsToCallNodes(ctx, chain)
}

// bfsToTarget runs BFS and reconstructs the path to target.
func bfsToTarget(cg *callgraph.Graph, queue []*ssa.Function, visited map[*ssa.Function]bool, parent map[*ssa.Function]*ssa.Function, target *ssa.Function) []*ssa.Function {
	for len(queue) > 0 {
		fn := queue[0]
		queue = queue[1:]
		if fn == target {
			return reconstructChain(parent, target)
		}
		node := cg.Nodes[fn]
		if node == nil {
			continue
		}
		for _, edge := range node.Out {
			callee := edge.Callee.Func
			if callee == nil || visited[callee] {
				continue
			}
			visited[callee] = true
			parent[callee] = fn
			queue = append(queue, callee)
		}
	}
	return nil
}

// reconstructChain builds the path from target back through parents.
func reconstructChain(parent map[*ssa.Function]*ssa.Function, target *ssa.Function) []*ssa.Function {
	var chain []*ssa.Function
	cur := target
	for cur != nil {
		chain = append(chain, cur)
		cur = parent[cur]
	}
	for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
		chain[i], chain[j] = chain[j], chain[i]
	}
	return chain
}

// functionsToCallNodes converts SSA functions to callNodes.
func functionsToCallNodes(ctx *analyzer.Context, chain []*ssa.Function) []callNode {
	nodes := make([]callNode, 0, len(chain))
	for _, fn := range chain {
		nodes = append(nodes, ssaToCallNode(ctx, fn))
	}
	return nodes
}

// findPotentialCallers finds functions that directly call the target,
// even if those callers are themselves unreachable (dead).
func findPotentialCallers(ctx *analyzer.Context, cg *callgraph.Graph, target *ssa.Function) []callNode {
	targetNode := cg.Nodes[target]
	if targetNode == nil {
		return nil
	}

	var callers []callNode
	for _, edge := range targetNode.In {
		if edge.Caller != nil && edge.Caller.Func != nil {
			callers = append(callers, ssaToCallNode(ctx, edge.Caller.Func))
		}
	}

	sort.Slice(callers, func(i, j int) bool {
		return callers[i].Function < callers[j].Function
	})

	if len(callers) == 0 {
		return nil
	}
	return callers
}

// findExternalCallers finds callers of the function from different packages.
func findExternalCallers(ctx *analyzer.Context, cg *callgraph.Graph, target *ssa.Function) []callNode {
	targetNode := cg.Nodes[target]
	if targetNode == nil {
		return nil
	}

	var external []callNode
	targetPkg := ssalookup.FuncPackage(target)
	for _, edge := range targetNode.In {
		if edge.Caller == nil || edge.Caller.Func == nil {
			continue
		}
		callerPkg := ssalookup.FuncPackage(edge.Caller.Func)
		if callerPkg != targetPkg {
			external = append(external, ssaToCallNode(ctx, edge.Caller.Func))
		}
	}
	return external
}

// ssaToCallNode converts an SSA function to a callNode.
func ssaToCallNode(ctx *analyzer.Context, fn *ssa.Function) callNode {
	return callNode{
		Function: ssalookup.CleanFuncName(fn),
		Location: ssalookup.FuncLocation(ctx, fn),
		Package:  ssalookup.FuncPackage(fn),
	}
}

// funcKind returns the kind label for a function.
func funcKind(fn *ssa.Function) string {
	if fn.Signature != nil && fn.Signature.Recv() != nil {
		return "method"
	}
	return "function"
}

// kindOf returns the kind string for a types.Object.
func kindOf(obj types.Object) string {
	switch obj.(type) {
	case *types.Func:
		return "function"
	case *types.TypeName:
		return "type"
	case *types.Var:
		return "variable"
	case *types.Const:
		return "constant"
	default:
		return "identifier"
	}
}

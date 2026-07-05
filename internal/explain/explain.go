// Package explain traces why a symbol is unused or dead, showing the
// call chain that would (or wouldn't) reach it.
package explain

import (
	"fmt"
	"go/types"
	"sort"
	"strings"

	"github.com/dovocoder/gollaw/internal/analyzer"
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
	fn := findFunction(ctx, symbolName)
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
	fn := findFunction(ctx, symbolName)
	if fn == nil {
		return nil, fmt.Errorf("function %q not found in the analyzed codebase", symbolName)
	}

	loc := funcLocation(ctx, fn)
	expl := &Explanation{Symbol: symbolName, Kind: funcKind(fn), Location: loc}

	cg := static.CallGraph(ctx.SSA)
	if isReachable(cg, fn) {
		expl.Status = "used"
		expl.Reason = fmt.Sprintf("function %s is reachable from an entry point", cleanFuncName(fn))
		expl.CallChain = findCallChainFromEntry(ctx, cg, fn)
		return expl, nil
	}

	expl.Status = "dead"
	expl.Reason = fmt.Sprintf("function %s is not reachable from any entry point (main, init, exported, or method). No call chain reaches it.", cleanFuncName(fn))
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

// findFunction searches all SSA packages for a function matching the given
// name. Matches against fn.Name(), fn.String(), and "Type.Method" patterns.
func findFunction(ctx *analyzer.Context, name string) *ssa.Function {
	if ctx.SSA == nil {
		return nil
	}
	for _, ssaPkg := range ctx.SSAByPkg {
		if ssaPkg == nil {
			continue
		}
		if fn := findFunctionInPackage(ssaPkg, name); fn != nil {
			return fn
		}
	}
	return nil
}

// findFunctionInPackage searches a single SSA package for a matching function.
func findFunctionInPackage(ssaPkg *ssa.Package, name string) *ssa.Function {
	for _, member := range ssaPkg.Members {
		if fn, ok := member.(*ssa.Function); ok {
			if matchFunctionName(fn, name) {
				return fn
			}
		}
		if typ, ok := member.(*ssa.Type); ok {
			if fn := findMethodOnType(ssaPkg, typ, name); fn != nil {
				return fn
			}
		}
	}
	return nil
}

// findMethodOnType searches for a method matching name on the given type
// and its pointer type.
func findMethodOnType(ssaPkg *ssa.Package, typ *ssa.Type, name string) *ssa.Function {
	ms := ssaPkg.Prog.MethodSets.MethodSet(typ.Type())
	for i := 0; i < ms.Len(); i++ {
		fn := ssaPkg.Prog.MethodValue(ms.At(i))
		if fn != nil && fn.Pkg == ssaPkg && matchFunctionName(fn, name) {
			return fn
		}
	}
	pointerType := types.NewPointer(typ.Type())
	ms2 := ssaPkg.Prog.MethodSets.MethodSet(pointerType)
	for i := 0; i < ms2.Len(); i++ {
		fn := ssaPkg.Prog.MethodValue(ms2.At(i))
		if fn != nil && fn.Pkg == ssaPkg && matchFunctionName(fn, name) {
			return fn
		}
	}
	return nil
}

// matchFunctionName checks if an SSA function matches the requested symbol name.
func matchFunctionName(fn *ssa.Function, name string) bool {
	if fn.Name() == name || fn.String() == name {
		return true
	}
	recv := fn.Signature.Recv()
	typeName := ""
	if recv != nil {
		typeName = recvTypeName(recv.Type())
		if typeName != "" && typeName+"."+fn.Name() == name {
			return true
		}
	}
	if cleanFuncName(fn) == name {
		return true
	}
	return matchLastComponent(fn, name, recv, typeName)
}

// matchLastComponent checks if the last component of a dotted name matches.
func matchLastComponent(fn *ssa.Function, name string, recv *types.Var, typeName string) bool {
	parts := strings.Split(name, ".")
	if len(parts) == 0 || fn.Name() != parts[len(parts)-1] {
		return false
	}
	if len(parts) >= 2 && recv != nil {
		return typeName == parts[len(parts)-2]
	}
	return len(parts) < 2 || recv == nil
}

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
	loc := funcLocation(ctx, fn)
	expl := &Explanation{Symbol: symbolName, Kind: funcKind(fn), Location: loc}

	cg := static.CallGraph(ctx.SSA)
	if isReachable(cg, fn) {
		setReachableStatus(expl, ctx, cg, fn)
	} else {
		expl.Status = "dead"
		expl.Reason = fmt.Sprintf("function %s is not reachable from any entry point", cleanFuncName(fn))
		expl.CallChain = findPotentialCallers(ctx, cg, fn)
	}
	return expl, nil
}

// setReachableStatus sets the explanation for a reachable function.
func setReachableStatus(expl *Explanation, ctx *analyzer.Context, cg *callgraph.Graph, fn *ssa.Function) {
	externalCallers := findExternalCallers(ctx, cg, fn)
	if len(externalCallers) == 0 {
		expl.Status = "unused"
		expl.Reason = fmt.Sprintf("function %s is reachable but only within its own package; not called externally", cleanFuncName(fn))
	} else {
		expl.Status = "used"
		expl.Reason = fmt.Sprintf("function %s is reachable and called externally", cleanFuncName(fn))
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
	targetPkg := funcPackage(target)
	for _, edge := range targetNode.In {
		if edge.Caller == nil || edge.Caller.Func == nil {
			continue
		}
		callerPkg := funcPackage(edge.Caller.Func)
		if callerPkg != targetPkg {
			external = append(external, ssaToCallNode(ctx, edge.Caller.Func))
		}
	}
	return external
}

// ssaToCallNode converts an SSA function to a callNode.
func ssaToCallNode(ctx *analyzer.Context, fn *ssa.Function) callNode {
	pos := ctx.FSET.Position(fn.Pos())
	return callNode{
		Function: cleanFuncName(fn),
		Location: fmt.Sprintf("%s:%d", pos.Filename, pos.Line),
		Package:  funcPackage(fn),
	}
}

// funcLocation returns "file:line" for an SSA function.
func funcLocation(ctx *analyzer.Context, fn *ssa.Function) string {
	pos := ctx.FSET.Position(fn.Pos())
	return fmt.Sprintf("%s:%d", pos.Filename, pos.Line)
}

// funcKind returns the kind label for a function.
func funcKind(fn *ssa.Function) string {
	if fn.Signature != nil && fn.Signature.Recv() != nil {
		return "method"
	}
	return "function"
}

// funcPackage returns the package path for a function.
func funcPackage(fn *ssa.Function) string {
	if fn.Pkg != nil && fn.Pkg.Pkg != nil {
		return fn.Pkg.Pkg.Path()
	}
	if fn.Object() != nil && fn.Object().Pkg() != nil {
		return fn.Object().Pkg().Path()
	}
	return ""
}

// cleanFuncName returns a readable "pkg.funcName" or "pkg.Type.Method" form.
func cleanFuncName(fn *ssa.Function) string {
	if fn.Object() != nil && fn.Object().Pkg() != nil {
		return fmt.Sprintf("%s.%s", fn.Object().Pkg().Name(), fn.Name())
	}
	if fn.Pkg != nil {
		return fmt.Sprintf("%s.%s", fn.Pkg.Pkg.Name(), fn.Name())
	}
	return fn.String()
}

// recvTypeName extracts the receiver type name.
func recvTypeName(t interface{}) string {
	if n, ok := t.(interface {
		Obj() interface{ Name() string }
	}); ok {
		return n.Obj().Name()
	}
	if p, ok := t.(interface {
		Elem() interface{}
	}); ok {
		return recvTypeName(p.Elem())
	}
	return ""
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

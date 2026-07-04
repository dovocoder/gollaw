// Package explain traces why a symbol is unused or dead, showing the
// call chain that would (or wouldn't) reach it.
package explain

import (
	"encoding/json"
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
	CallChain []CallNode `json:"callChain"`  // who calls it, transitively (entry → ... → target)
	Reason    string     `json:"reason"`
}

// CallNode is a single node in a call chain.
type CallNode struct {
	Function string `json:"function"`
	Location string `json:"location"` // file:line
	Package  string `json:"package"`
}

// ExplainUnused finds a symbol by name and explains why it is unused
// (never referenced outside its own package or never called at all).
func ExplainUnused(ctx *analyzer.Context, symbolName string) (*Explanation, error) {
	// First, try to find it as a function/method in SSA.
	fn := findFunction(ctx, symbolName)
	if fn != nil {
		return explainUnusedFunction(ctx, fn, symbolName)
	}

	// Otherwise, look for it as an exported type/variable/constant.
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
	expl := &Explanation{
		Symbol:   symbolName,
		Kind:     funcKind(fn),
		Location: loc,
	}

	// Build the call graph and check reachability.
	cg := static.CallGraph(ctx.SSA)
	reachable := isReachable(cg, fn)

	if reachable {
		expl.Status = "used"
		expl.Reason = fmt.Sprintf("function %s is reachable from an entry point", cleanFuncName(fn))
		expl.CallChain = findCallChainFromEntry(ctx, cg, fn)
		return expl, nil
	}

	expl.Status = "dead"
	expl.Reason = fmt.Sprintf("function %s is not reachable from any entry point (main, init, exported, or method). No call chain reaches it.", cleanFuncName(fn))

	// Show what functions *could* call it if they were made reachable.
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

	if len(e.CallChain) > 0 {
		fmt.Fprintf(&b, "Call chain:\n")
		for i, node := range e.CallChain {
			if i == len(e.CallChain)-1 && e.Status != "dead" {
				fmt.Fprintf(&b, "  → %s  (%s)  [%s]  ← target\n", node.Function, node.Location, node.Package)
			} else {
				fmt.Fprintf(&b, "  → %s  (%s)  [%s]\n", node.Function, node.Location, node.Package)
			}
		}
	} else {
		fmt.Fprintf(&b, "Call chain: (none found)\n")
	}

	fmt.Fprintf(&b, "\nReason: %s\n", e.Reason)

	return b.String()
}

// FormatExplanationJSON produces a JSON explanation.
func FormatExplanationJSON(e *Explanation) ([]byte, error) {
	return json.MarshalIndent(e, "", "  ")
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
		// Package-level functions.
		for _, member := range ssaPkg.Members {
			if fn, ok := member.(*ssa.Function); ok {
				if matchFunctionName(fn, name) {
					return fn
				}
			}
			// Methods on named types.
			if typ, ok := member.(*ssa.Type); ok {
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
			}
		}
	}
	return nil
}

// matchFunctionName checks if an SSA function matches the requested symbol name.
func matchFunctionName(fn *ssa.Function, name string) bool {
	if fn.Name() == name {
		return true
	}
	if fn.String() == name {
		return true
	}
	// Check "Type.Method" form.
	recv := fn.Signature.Recv()
	if recv != nil {
		typeName := recvTypeName(recv.Type())
		if typeName != "" {
			if typeName+"."+fn.Name() == name {
				return true
			}
		}
	}
	// Check "pkg.funcName" form.
	cleanName := cleanFuncName(fn)
	if cleanName == name {
		return true
	}
	// Check if the last component of a dotted name matches.
	parts := strings.Split(name, ".")
	if len(parts) > 0 && fn.Name() == parts[len(parts)-1] {
		// If name has "Type.Method", check that too.
		if len(parts) >= 2 && recv != nil {
			if recvTypeName(recv.Type()) == parts[len(parts)-2] && fn.Name() == parts[len(parts)-1] {
				return true
			}
		}
	}
	return false
}

// findTypeObject searches for a non-function exported symbol (type, var, const).
func findTypeObject(ctx *analyzer.Context, name string) types.Object {
	for _, typPkg := range ctx.TypesByPkg {
		scope := typPkg.Scope()
		// Allow "pkg.Name" or just "Name".
		parts := strings.Split(name, ".")
		lookupName := name
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
	expl := &Explanation{
		Symbol:   symbolName,
		Kind:     funcKind(fn),
		Location: loc,
	}

	cg := static.CallGraph(ctx.SSA)
	reachable := isReachable(cg, fn)

	if reachable {
		// It's called — check if it's only called within its own package.
		externalCallers := findExternalCallers(ctx, cg, fn)
		if len(externalCallers) == 0 {
			expl.Status = "unused"
			expl.Reason = fmt.Sprintf("function %s is reachable but only within its own package; not called externally", cleanFuncName(fn))
		} else {
			expl.Status = "used"
			expl.Reason = fmt.Sprintf("function %s is reachable and called externally", cleanFuncName(fn))
		}
		expl.CallChain = findCallChainFromEntry(ctx, cg, fn)
	} else {
		expl.Status = "dead"
		expl.Reason = fmt.Sprintf("function %s is not reachable from any entry point", cleanFuncName(fn))
		expl.CallChain = findPotentialCallers(ctx, cg, fn)
	}

	return expl, nil
}

// explainUnusedObject creates an explanation for an unused type/variable/constant.
func explainUnusedObject(ctx *analyzer.Context, obj types.Object, symbolName string) (*Explanation, error) {
	pos := ctx.FSET.Position(obj.Pos())
	expl := &Explanation{
		Symbol:   symbolName,
		Kind:     kindOf(obj),
		Location: fmt.Sprintf("%s:%d", pos.Filename, pos.Line),
	}

	// Check if the object is used outside its package.
	usedExternally := false
	for _, pkg := range ctx.Packages {
		if pkg.TypesInfo == nil {
			continue
		}
		if pkg.PkgPath == obj.Pkg().Path() {
			continue
		}
		for _, usedObj := range pkg.TypesInfo.Uses {
			if usedObj == obj {
				usedExternally = true
				break
			}
		}
		if usedExternally {
			break
		}
	}

	if usedExternally {
		expl.Status = "used"
		expl.Reason = fmt.Sprintf("%s %s is referenced outside its defining package", expl.Kind, symbolName)
	} else {
		expl.Status = "unused"
		expl.Reason = fmt.Sprintf("%s %s is not referenced outside its defining package", expl.Kind, symbolName)
	}

	return expl, nil
}

// isReachable checks if the given function is reachable from any entry point
// in the call graph.
func isReachable(cg *callgraph.Graph, target *ssa.Function) bool {
	// Build a reverse edge map: callee → set of callers.
	callerMap := make(map[*callgraph.Node]bool)
	queue := []*callgraph.Node{}

	addIfNew := func(n *callgraph.Node) {
		if n != nil && !callerMap[n] {
			callerMap[n] = true
			queue = append(queue, n)
		}
	}

	// Entry points: main, init, exported functions/methods.
	for _, n := range cg.Nodes {
		if n == nil || n.Func == nil {
			continue
		}
		fn := n.Func
		if fn.Name() == "main" || fn.Name() == "init" {
			addIfNew(n)
		}
		if fn.Object() != nil && fn.Object().Exported() {
			addIfNew(n)
		}
		if fn.Signature != nil && fn.Signature.Recv() != nil {
			addIfNew(n) // methods can be called via interface
		}
	}

	visited := make(map[*callgraph.Node]bool)
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
			if edge.Callee != nil {
				addIfNew(edge.Callee)
			}
		}
	}
	return false
}

// findCallChainFromEntry performs a BFS from entry points to the target,
// returning the call chain (entry → ... → target).
func findCallChainFromEntry(ctx *analyzer.Context, cg *callgraph.Graph, target *ssa.Function) []CallNode {
	type chainNode struct {
		fn   *ssa.Function
		depth int
	}

	// BFS from entry points to target, tracking parent for path reconstruction.
	parent := make(map[*ssa.Function]*ssa.Function)
	visited := make(map[*ssa.Function]bool)
	var queue []*ssa.Function

	addEntry := func(fn *ssa.Function) {
		if fn == nil || visited[fn] {
			return
		}
		visited[fn] = true
		queue = append(queue, fn)
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

	found := false
	for len(queue) > 0 && !found {
		fn := queue[0]
		queue = queue[1:]
		if fn == target {
			found = true
			break
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

	if !found {
		return nil
	}

	// Reconstruct path.
	var chain []*ssa.Function
	cur := target
	for cur != nil {
		chain = append(chain, cur)
		cur = parent[cur]
	}

	// Reverse to get entry → ... → target.
	for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
		chain[i], chain[j] = chain[j], chain[i]
	}

	nodes := make([]CallNode, 0, len(chain))
	for _, fn := range chain {
		nodes = append(nodes, ssaToCallNode(ctx, fn))
	}
	return nodes
}

// findPotentialCallers finds functions that directly call the target,
// even if those callers are themselves unreachable (dead).
func findPotentialCallers(ctx *analyzer.Context, cg *callgraph.Graph, target *ssa.Function) []CallNode {
	targetNode := cg.Nodes[target]
	if targetNode == nil {
		return nil
	}

	var callers []CallNode
	for _, edge := range targetNode.In {
		if edge.Caller != nil && edge.Caller.Func != nil {
			callers = append(callers, ssaToCallNode(ctx, edge.Caller.Func))
		}
	}

	// Sort by function name for stable output.
	sort.Slice(callers, func(i, j int) bool {
		return callers[i].Function < callers[j].Function
	})

	if len(callers) == 0 {
		return nil
	}
	return callers
}

// findExternalCallers finds callers of the function from different packages.
func findExternalCallers(ctx *analyzer.Context, cg *callgraph.Graph, target *ssa.Function) []CallNode {
	targetNode := cg.Nodes[target]
	if targetNode == nil {
		return nil
	}

	var external []CallNode
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

// ssaToCallNode converts an SSA function to a CallNode.
func ssaToCallNode(ctx *analyzer.Context, fn *ssa.Function) CallNode {
	pos := ctx.FSET.Position(fn.Pos())
	pkg := funcPackage(fn)
	return CallNode{
		Function: cleanFuncName(fn),
		Location: fmt.Sprintf("%s:%d", pos.Filename, pos.Line),
		Package:  pkg,
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

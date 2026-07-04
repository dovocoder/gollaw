// Package trace provides symbol-level call-chain tracing: "who calls X,
// transitively" and "what does X call".
package trace

import (
	"encoding/json"
	"fmt"
	"go/types"
	"sort"
	"strings"

	"github.com/dovocoder/gollaw/internal/analyzer"
	"golang.org/x/tools/go/callgraph/static"
	"golang.org/x/tools/go/ssa"
)

const defaultMaxDepth = 10

// TraceResult holds the result of a call-chain trace.
type TraceResult struct {
	Symbol     string       `json:"symbol"`
	Direction  string       `json:"direction"` // "callers" or "callees"
	Chains     [][]TraceNode `json:"chains"`
	TotalPaths int          `json:"totalPaths"`
}

// TraceNode is a single node in a call chain.
type TraceNode struct {
	Function string `json:"function"`
	Location string `json:"location"` // file:line
	Package  string `json:"package"`
	Depth    int    `json:"depth"`
}

// TraceCallers finds all functions that call the given symbol, transitively,
// up to maxDepth levels. If maxDepth <= 0, defaultMaxDepth is used.
func TraceCallers(ctx *analyzer.Context, symbolName string, maxDepth int) (*TraceResult, error) {
	if ctx.SSA == nil {
		return nil, fmt.Errorf("SSA program not available")
	}
	if maxDepth <= 0 {
		maxDepth = defaultMaxDepth
	}

	fn := findFunction(ctx, symbolName)
	if fn == nil {
		return nil, fmt.Errorf("function %q not found in the analyzed codebase", symbolName)
	}

	cg := static.CallGraph(ctx.SSA)

	// Build reverse edges: for each function, who calls it?
	// callgraph.Graph edges are: Caller → Callee. We need Callee → Caller.
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

	// DFS to find all paths from callers up to the target.
	var chains [][]TraceNode
	visited := make(map[string]bool)
	path := []TraceNode{}

	var dfs func(current *ssa.Function, depth int)
	dfs = func(current *ssa.Function, depth int) {
		key := current.String()
		if visited[key] {
			return // avoid cycles
		}
		if depth > maxDepth {
			return
		}

		visited[key] = true
		path = append(path, TraceNode{
			Function: cleanFuncName(current),
			Location: funcLocation(ctx, current),
			Package:  funcPackage(current),
			Depth:    depth,
		})

		callers := reverseEdges[current]
		if len(callers) == 0 || depth == maxDepth {
			// This is a path endpoint (entry point or max depth reached).
			if len(path) > 1 {
				chain := make([]TraceNode, len(path))
				// Reverse: entry → ... → target.
				for i, j := 0, len(path)-1; j >= 0; i, j = i+1, j-1 {
					chain[i] = path[j]
				}
				chains = append(chains, chain)
			}
		} else {
			for _, caller := range callers {
				dfs(caller, depth+1)
			}
		}

		path = path[:len(path)-1]
		visited[key] = false // allow other paths through this node
	}

	dfs(fn, 0)

	// If no chains found (no callers), include the target itself.
	if len(chains) == 0 {
		chains = append(chains, []TraceNode{{
			Function: cleanFuncName(fn),
			Location: funcLocation(ctx, fn),
			Package:  funcPackage(fn),
			Depth:    0,
		}})
	}

	return &TraceResult{
		Symbol:     symbolName,
		Direction:  "callers",
		Chains:     chains,
		TotalPaths: len(chains),
	}, nil
}

// TraceCallees finds all functions called by the given symbol, transitively,
// up to maxDepth levels. If maxDepth <= 0, defaultMaxDepth is used.
func TraceCallees(ctx *analyzer.Context, symbolName string, maxDepth int) (*TraceResult, error) {
	if ctx.SSA == nil {
		return nil, fmt.Errorf("SSA program not available")
	}
	if maxDepth <= 0 {
		maxDepth = defaultMaxDepth
	}

	fn := findFunction(ctx, symbolName)
	if fn == nil {
		return nil, fmt.Errorf("function %q not found in the analyzed codebase", symbolName)
	}

	cg := static.CallGraph(ctx.SSA)

	var chains [][]TraceNode
	visited := make(map[string]bool)
	path := []TraceNode{}

	var dfs func(current *ssa.Function, depth int)
	dfs = func(current *ssa.Function, depth int) {
		key := current.String()
		if visited[key] {
			return // avoid cycles
		}
		if depth > maxDepth {
			return
		}

		visited[key] = true
		path = append(path, TraceNode{
			Function: cleanFuncName(current),
			Location: funcLocation(ctx, current),
			Package:  funcPackage(current),
			Depth:    depth,
		})

		node := cg.Nodes[current]
		var callees []*ssa.Function
		if node != nil {
			for _, edge := range node.Out {
				if edge.Callee != nil && edge.Callee.Func != nil {
					callees = append(callees, edge.Callee.Func)
				}
			}
		}

		if len(callees) == 0 || depth == maxDepth {
			// Path endpoint.
			if len(path) > 1 {
				chain := make([]TraceNode, len(path))
				copy(chain, path)
				chains = append(chains, chain)
			}
		} else {
			for _, callee := range callees {
				dfs(callee, depth+1)
			}
		}

		path = path[:len(path)-1]
		visited[key] = false // allow other paths through this node
	}

	dfs(fn, 0)

	// If no chains found (no callees), include the target itself.
	if len(chains) == 0 {
		chains = append(chains, []TraceNode{{
			Function: cleanFuncName(fn),
			Location: funcLocation(ctx, fn),
			Package:  funcPackage(fn),
			Depth:    0,
		}})
	}

	return &TraceResult{
		Symbol:     symbolName,
		Direction:  "callees",
		Chains:     chains,
		TotalPaths: len(chains),
	}, nil
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

	for i, chain := range result.Chains {
		fmt.Fprintf(&b, "Path %d:\n", i+1)
		for j, node := range chain {
			indent := strings.Repeat("  ", j)
			arrow := "→"
			if j == 0 {
				arrow = "◆"
			}
			if j == len(chain)-1 && j > 0 {
				arrow = "▸"
			}
			fmt.Fprintf(&b, "%s%s %s  (%s)  [%s]\n", indent, arrow, node.Function, node.Location, node.Package)
		}
		fmt.Fprintf(&b, "\n")
	}

	return b.String()
}

// FormatTraceJSON produces a JSON trace result.
func FormatTraceJSON(result *TraceResult) ([]byte, error) {
	return json.MarshalIndent(result, "", "  ")
}

// ─── Internal helpers ────────────────────────────────────────────────

// findFunction searches all SSA packages for a function matching the given
// name. Matches against fn.Name(), fn.String(), "Type.Method", and "pkg.func".
func findFunction(ctx *analyzer.Context, name string) *ssa.Function {
	for _, ssaPkg := range ctx.SSAByPkg {
		if ssaPkg == nil {
			continue
		}
		for _, member := range ssaPkg.Members {
			if fn, ok := member.(*ssa.Function); ok {
				if matchFunctionName(fn, name) {
					return fn
				}
			}
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
	recv := fn.Signature.Recv()
	if recv != nil {
		typeName := recvTypeName(recv.Type())
		if typeName != "" {
			if typeName+"."+fn.Name() == name {
				return true
			}
		}
	}
	cleanName := cleanFuncName(fn)
	if cleanName == name {
		return true
	}
	parts := strings.Split(name, ".")
	if len(parts) > 0 && fn.Name() == parts[len(parts)-1] {
		if len(parts) >= 2 && recv != nil {
			if recvTypeName(recv.Type()) == parts[len(parts)-2] && fn.Name() == parts[len(parts)-1] {
				return true
			}
		}
		return true
	}
	return false
}

// funcLocation returns "file:line" for an SSA function.
func funcLocation(ctx *analyzer.Context, fn *ssa.Function) string {
	pos := ctx.FSET.Position(fn.Pos())
	return fmt.Sprintf("%s:%d", pos.Filename, pos.Line)
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

// cleanFuncName returns a readable "pkg.funcName" form.
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

// sortedChains sorts chains by their string representation for stable output.
func sortedChains(chains [][]TraceNode) {
	sort.Slice(chains, func(i, j int) bool {
		si := chainKey(chains[i])
		sj := chainKey(chains[j])
		return si < sj
	})
}

func chainKey(chain []TraceNode) string {
	var b strings.Builder
	for _, n := range chain {
		b.WriteString(n.Function)
		b.WriteString("|")
	}
	return b.String()
}

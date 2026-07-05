package analyzer

import (
	"fmt"
	"go/token"
	"go/types"
	"sort"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/callgraph/static"
	"golang.org/x/tools/go/ssa"
)

// deadCodeAnalyzer finds unreachable functions using the SSA call graph.
type deadCodeAnalyzer struct{}

func newDeadCodeAnalyzer() *deadCodeAnalyzer { return &deadCodeAnalyzer{} }

func (a *deadCodeAnalyzer) Name() string        { return "deadcode" }
func (a *deadCodeAnalyzer) Category() Category  { return CategoryDeadCode }
func (a *deadCodeAnalyzer) Description() string { return "Detects unreachable functions via SSA call graph analysis" }

func (a *deadCodeAnalyzer) Analyze(ctx *Context) ([]Finding, error) {
	if ctx.SSA == nil {
		return nil, fmt.Errorf("SSA program not available")
	}

	allFns := a.collectAllFunctions(ctx.SSAByPkg)
	reachable := a.buildReachableSet(ctx, allFns)
	deadFns := a.findDeadFunctions(allFns, reachable)
	return a.createFindings(ctx, deadFns), nil
}

// collectAllFunctions gathers all non-test, non-init, non-main functions
// from the target packages (not dependencies).
func (a *deadCodeAnalyzer) collectAllFunctions(ssaByPkg map[string]*ssa.Package) map[string]*ssa.Function {
	allFns := make(map[string]*ssa.Function)
	collect := func(fn *ssa.Function) {
		if fn == nil || fn.Name() == "" || fn.Syntax() == nil {
			return
		}
		if fn.Name() == "init" || fn.Name() == "main" {
			return
		}
		if isTestFunction(fn) {
			return
		}
		allFns[fn.String()] = fn
	}

	for _, ssaPkg := range ssaByPkg {
		if ssaPkg == nil {
			continue
		}
		for _, member := range ssaPkg.Members {
			collectPackageMember(ssaPkg, member, collect)
		}
	}
	return allFns
}

// collectPackageMember collects functions from a package member, including
// methods on named types (both value and pointer receivers).
func collectPackageMember(ssaPkg *ssa.Package, member ssa.Member, collect func(*ssa.Function)) {
	if fn, ok := member.(*ssa.Function); ok {
		collect(fn)
	}
	typ, ok := member.(*ssa.Type)
	if !ok {
		return
	}
	collectMethodSet(ssaPkg, typ.Type(), collect)
	pointerType := types.NewPointer(typ.Type())
	collectMethodSet(ssaPkg, pointerType, collect)
}

// collectMethodSet collects all methods in the method set of a type
// that belong to the given package.
func collectMethodSet(ssaPkg *ssa.Package, recvType types.Type, collect func(*ssa.Function)) {
	ms := ssaPkg.Prog.MethodSets.MethodSet(recvType)
	for i := 0; i < ms.Len(); i++ {
		fn := ssaPkg.Prog.MethodValue(ms.At(i))
		if fn != nil && fn.Pkg == ssaPkg {
			collect(fn)
		}
	}
}

// buildReachableSet performs a BFS from entry points through the call graph
// and SSA instructions to determine which functions are reachable.
func (a *deadCodeAnalyzer) buildReachableSet(ctx *Context, allFns map[string]*ssa.Function) map[string]bool {
	cg := static.CallGraph(ctx.SSA)
	reachable := make(map[string]bool)
	var queue []*ssa.Function

	addEntry := func(fn *ssa.Function) {
		key := fn.String()
		if !reachable[key] {
			reachable[key] = true
			queue = append(queue, fn)
		}
	}

	a.seedEntryPoints(allFns, addEntry)
	a.bfsReachable(cg, allFns, queue, addEntry)
	return reachable
}

// seedEntryPoints marks main, init, exported, and method functions as
// initial entry points.
func (a *deadCodeAnalyzer) seedEntryPoints(allFns map[string]*ssa.Function, addEntry func(*ssa.Function)) {
	for _, fn := range allFns {
		if fn.Name() == "main" || fn.Name() == "init" {
			addEntry(fn)
			continue
		}
		if isExportedSSA(fn) {
			addEntry(fn)
			continue
		}
		// Method on any type — could be called via interface.
		if fn.Signature != nil && fn.Signature.Recv() != nil {
			addEntry(fn)
		}
	}
}

// bfsReachable performs the breadth-first traversal of the call graph,
// falling back to SSA instruction scanning when call graph edges are absent.
func (a *deadCodeAnalyzer) bfsReachable(cg *callgraph.Graph, allFns map[string]*ssa.Function, queue []*ssa.Function, addEntry func(*ssa.Function)) {
	for len(queue) > 0 {
		fn := queue[0]
		queue = queue[1:]

		if node := cg.Nodes[fn]; node != nil {
			a.processCallGraphEdges(node, allFns, addEntry)
			continue
		}
		a.scanSSAInstructions(fn, allFns, addEntry)
	}
}

// processCallGraphEdges visits callees reachable via call graph edges.
func (a *deadCodeAnalyzer) processCallGraphEdges(node *callgraph.Node, allFns map[string]*ssa.Function, addEntry func(*ssa.Function)) {
	for _, edge := range node.Out {
		callee := edge.Callee.Func
		if _, exists := allFns[callee.String()]; exists {
			addEntry(callee)
		}
	}
}

// scanSSAInstructions scans SSA instructions for direct call sites
// (calls, goroutine launches, deferred calls).
func (a *deadCodeAnalyzer) scanSSAInstructions(fn *ssa.Function, allFns map[string]*ssa.Function, addEntry func(*ssa.Function)) {
	if fn.Blocks == nil {
		return
	}
	for _, block := range fn.Blocks {
		for _, instr := range block.Instrs {
			a.processSSAInstruction(instr, allFns, addEntry)
		}
	}
}

// processSSAInstruction checks a single SSA instruction for call sites.
func (a *deadCodeAnalyzer) processSSAInstruction(instr ssa.Instruction, allFns map[string]*ssa.Function, addEntry func(*ssa.Function)) {
	var callee *ssa.Function
	switch v := instr.(type) {
	case *ssa.Call:
		callee = v.Common().StaticCallee()
	case *ssa.Go:
		callee = v.Common().StaticCallee()
	case *ssa.Defer:
		callee = v.Common().StaticCallee()
	}
	if callee == nil {
		return
	}
	if _, exists := allFns[callee.String()]; exists {
		addEntry(callee)
	}
}

// findDeadFunctions returns functions in allFns that are not in reachable,
// sorted by position.
func (a *deadCodeAnalyzer) findDeadFunctions(allFns map[string]*ssa.Function, reachable map[string]bool) []*ssa.Function {
	var deadFns []*ssa.Function
	for key, fn := range allFns {
		if !reachable[key] {
			deadFns = append(deadFns, fn)
		}
	}
	sort.Slice(deadFns, func(i, j int) bool {
		return deadFns[i].Pos() < deadFns[j].Pos()
	})
	return deadFns
}

// createFindings converts dead functions into Finding objects.
func (a *deadCodeAnalyzer) createFindings(ctx *Context, deadFns []*ssa.Function) []Finding {
	var findings []Finding
	for _, fn := range deadFns {
		pos := ctx.FSET.Position(fn.Pos())
		findings = append(findings, Finding{
			Analyzer:  a.Name(),
			Category:  a.Category(),
			Severity:  SeverityWarning,
			Message:    fmt.Sprintf("unreachable function %s", cleanFuncName(fn)),
			File:       pos.Filename,
			Line:       pos.Line,
			EndLine:    pos.Line,
			RuleID:     "GLW-DC001",
			Suggestion: "Remove this function or add a caller. If it is used via reflection or interface dispatch, add a //gollaw:keep comment.",
		})
	}
	return findings
}

func isExportedSSA(fn *ssa.Function) bool {
	if fn.Object() != nil {
		return fn.Object().Exported()
	}
	// Method on an exported type is a potential external entry point.
	if fn.Signature != nil && fn.Signature.Recv() != nil {
		named := recvTypeName(fn.Signature.Recv().Type())
		if named != "" && named[0] >= 'A' && named[0] <= 'Z' {
			return true
		}
	}
	return false
}

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

//gollaw:keep
func isTestFunction(fn *ssa.Function) bool {
	name := fn.Name()
	return len(name) > 4 && (name[:4] == "Test" || name[:4] == "Bench" || name[:4] == "Fuzz" || name == "TestMain")
}

func cleanFuncName(fn *ssa.Function) string {
	if fn.Object() != nil && fn.Object().Pkg() != nil {
		return fmt.Sprintf("%s.%s", fn.Object().Pkg().Name(), fn.Name())
	}
	if fn.Pkg != nil {
		return fmt.Sprintf("%s.%s", fn.Pkg.Pkg.Name(), fn.Name())
	}
	return fn.String()
}

var _ = token.NoPos
var _ = callgraph.New

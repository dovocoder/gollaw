package analyzer

import (
	"fmt"
	"go/types"
	"sort"

	"golang.org/x/tools/go/ssa"
)

// deadCodeAnalyzer finds unreachable functions by walking SSA instructions
// from entry points. This approach mirrors golang.org/x/tools/cmd/deadcode
// which uses Rapid Type Analysis (RTA): start from roots (main, init,
// exported functions, methods) and follow every SSA call instruction to
// discover reachable callees.
//
// Key design decisions:
//   - We do NOT use static.CallGraph because its Nodes map is keyed by
//     *ssa.Function pointer, which may differ from the pointers collected
//     from ssaPkg.Members — causing silent edge drops.
//   - We walk SSA instructions directly, which handles intra-package calls,
//     closures, and anonymous functions correctly.
//   - Methods are seeded as entry points because they may be called via
//     interface dispatch, which static call analysis cannot track.
type deadCodeAnalyzer struct{}

func newDeadCodeAnalyzer() *deadCodeAnalyzer { return &deadCodeAnalyzer{} }

func (a *deadCodeAnalyzer) Name() string        { return "deadcode" }
func (a *deadCodeAnalyzer) Category() Category   { return CategoryDeadCode }
func (a *deadCodeAnalyzer) Description() string   { return "Detects unreachable functions via SSA instruction analysis" }

func (a *deadCodeAnalyzer) Analyze(ctx *Context) ([]Finding, error) {
	if ctx.SSA == nil {
		return nil, fmt.Errorf("SSA program not available")
	}

	allFns := a.collectAllFunctions(ctx.SSAByPkg)
	reachable := a.buildReachableSet(allFns)
	deadFns := a.findDeadFunctions(allFns, reachable)
	return a.createFindings(ctx, deadFns), nil
}

// collectAllFunctions gathers all non-test functions from the target
// packages (not dependencies). main and init are included so they can
// serve as BFS entry points — they are filtered from findings later.
func (a *deadCodeAnalyzer) collectAllFunctions(ssaByPkg map[string]*ssa.Package) map[string]*ssa.Function {
	allFns := make(map[string]*ssa.Function)
	collect := func(fn *ssa.Function) {
		if fn == nil || fn.Name() == "" {
			return
		}
		// Skip synthetic functions except init — init is synthetic but
		// contains the package-level initializer code that references
		// function values (e.g. migration tables, cobra AddCommand).
		if fn.Syntax() == nil && fn.Name() != "init" {
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

// buildReachableSet performs a BFS from entry points, walking SSA
// instructions to discover all reachable functions.
//
// The queue is captured by the addEntry closure — when scanSSAInstructions
// discovers a new callee, addEntry appends it to the same queue that the
// BFS loop drains. This is critical: passing the queue as a parameter to
// a separate function would create a copy of the slice header, breaking
// the append-then-drain cycle.
func (a *deadCodeAnalyzer) buildReachableSet(allFns map[string]*ssa.Function) map[string]bool {
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

	// BFS: walk SSA instructions of each reachable function.
	visited := make(map[string]bool)
	for len(queue) > 0 {
		fn := queue[0]
		queue = queue[1:]
		a.scanSSAInstructions(fn, allFns, addEntry, visited)
	}
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
		// Method on any type — could be called via interface dispatch.
		if fn.Signature != nil && fn.Signature.Recv() != nil {
			addEntry(fn)
		}
	}
}

// scanSSAInstructions scans SSA instructions for direct call sites
// (calls, goroutine launches, deferred calls) and recursively visits
// closures (anonymous functions) that contain calls to tracked functions.
func (a *deadCodeAnalyzer) scanSSAInstructions(fn *ssa.Function, allFns map[string]*ssa.Function, addEntry func(*ssa.Function), visited map[string]bool) {
	if fn.Blocks == nil {
		return
	}
	for _, block := range fn.Blocks {
		for _, instr := range block.Instrs {
			a.processInstruction(instr, allFns, addEntry, visited)
		}
	}
}

// processInstruction checks a single SSA instruction for static calls,
// closure creation, and function values stored in variables/structs.
func (a *deadCodeAnalyzer) processInstruction(instr ssa.Instruction, allFns map[string]*ssa.Function, addEntry func(*ssa.Function), visited map[string]bool) {
	if callee := extractStaticCallee(instr); callee != nil {
		// Check both the callee itself and its origin (for generic instantiations).
		if _, exists := allFns[callee.String()]; exists {
			addEntry(callee)
		} else if origin := callee.Origin(); origin != nil {
			if _, exists := allFns[origin.String()]; exists {
				addEntry(origin)
			}
		}
	}
	a.scanClosure(instr, allFns, addEntry, visited)
	a.scanFunctionValues(instr, allFns, addEntry)
}

// scanFunctionValues checks for function values referenced in Store,
// ChangeInterface, and other instructions that don't involve a direct
// call. This catches patterns like:
//
//	var migrations = []migration{{up: migrateFoo}}
//	rootCmd.AddCommand(newFooCmd())
//
// where the function is referenced as a value, not called directly.
func (a *deadCodeAnalyzer) scanFunctionValues(instr ssa.Instruction, allFns map[string]*ssa.Function, addEntry func(*ssa.Function)) {
	// Check Store instructions: *t = someFunction
	if store, ok := instr.(*ssa.Store); ok {
		if fn, ok := store.Val.(*ssa.Function); ok {
			if _, exists := allFns[fn.String()]; exists {
				addEntry(fn)
			}
		}
	}
	// Check ChangeInterface instructions (function → interface{})
	if ci, ok := instr.(*ssa.ChangeInterface); ok {
		if fn, ok := ci.X.(*ssa.Function); ok {
			if _, exists := allFns[fn.String()]; exists {
				addEntry(fn)
			}
		}
	}
	// Check MakeInterface instructions (function → interface{})
	if mi, ok := instr.(*ssa.MakeInterface); ok {
		if fn, ok := mi.X.(*ssa.Function); ok {
			if _, exists := allFns[fn.String()]; exists {
				addEntry(fn)
			}
		}
	}
}

// scanClosure checks if an instruction creates a closure and, if so,
// recursively scans the closure's body for more call sites.
func (a *deadCodeAnalyzer) scanClosure(instr ssa.Instruction, allFns map[string]*ssa.Function, addEntry func(*ssa.Function), visited map[string]bool) {
	mc, ok := instr.(*ssa.MakeClosure)
	if !ok {
		return
	}
	closureFn, ok := mc.Fn.(*ssa.Function)
	if !ok {
		return
	}
	closureKey := closureFn.String()
	if visited[closureKey] {
		return
	}
	visited[closureKey] = true
	a.scanSSAInstructions(closureFn, allFns, addEntry, visited)
}

// extractStaticCallee returns the statically-known callee function from a
// call instruction (Call, Go, Defer), or nil if the call is dynamic.
func extractStaticCallee(instr ssa.Instruction) *ssa.Function {
	switch v := instr.(type) {
	case *ssa.Call:
		return v.Common().StaticCallee()
	case *ssa.Go:
		return v.Common().StaticCallee()
	case *ssa.Defer:
		return v.Common().StaticCallee()
	}
	return nil
}

// findDeadFunctions returns functions in allFns that are not in reachable,
// sorted by position. main and init are never reported as dead.
func (a *deadCodeAnalyzer) findDeadFunctions(allFns map[string]*ssa.Function, reachable map[string]bool) []*ssa.Function {
	var deadFns []*ssa.Function
	for key, fn := range allFns {
		if !reachable[key] {
			// Never report main or init as dead — they are program entry points.
			if fn.Name() == "main" || fn.Name() == "init" {
				continue
			}
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

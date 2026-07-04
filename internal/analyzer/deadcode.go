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

	// Collect all functions in the target packages (not dependencies).
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

	for _, ssaPkg := range ctx.SSAByPkg {
		if ssaPkg == nil {
			continue
		}
		// Package-level functions.
		for _, member := range ssaPkg.Members {
			if fn, ok := member.(*ssa.Function); ok {
				collect(fn)
			}
			// Methods on named types (both value and pointer receivers).
			if typ, ok := member.(*ssa.Type); ok {
				// Value receiver methods.
				ms := ssaPkg.Prog.MethodSets.MethodSet(typ.Type())
				for i := 0; i < ms.Len(); i++ {
					fn := ssaPkg.Prog.MethodValue(ms.At(i))
					if fn != nil && fn.Pkg == ssaPkg {
						collect(fn)
					}
				}
				// Pointer receiver methods.
				pointerType := types.NewPointer(typ.Type())
				ms2 := ssaPkg.Prog.MethodSets.MethodSet(pointerType)
				for i := 0; i < ms2.Len(); i++ {
					fn := ssaPkg.Prog.MethodValue(ms2.At(i))
					if fn != nil && fn.Pkg == ssaPkg {
						collect(fn)
					}
				}
			}
		}
	}

	// Build reachability set using the static call graph + manual SSA traversal.
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

	// Entry points: main, init, exported functions/methods, AND all methods
	// (since methods can be called via interface dispatch, which static
	// call graph analysis cannot fully resolve).
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

	// BFS: use call graph edges if available, otherwise scan SSA instructions.
	for len(queue) > 0 {
		fn := queue[0]
		queue = queue[1:]

		// Try the call graph first.
		if node := cg.Nodes[fn]; node != nil {
			for _, edge := range node.Out {
				callee := edge.Callee.Func
				if _, exists := allFns[callee.String()]; exists {
					addEntry(callee)
				}
			}
			continue
		}

		// Fallback: manually scan SSA instructions for call sites.
		if fn.Blocks == nil {
			continue
		}
		for _, block := range fn.Blocks {
			for _, instr := range block.Instrs {
				// Direct calls.
				if call, ok := instr.(*ssa.Call); ok {
					callee := call.Common().StaticCallee()
					if callee != nil {
						if _, exists := allFns[callee.String()]; exists {
							addEntry(callee)
						}
					}
				}
				// Goroutine launches.
				if goInstr, ok := instr.(*ssa.Go); ok {
					callee := goInstr.Common().StaticCallee()
					if callee != nil {
						if _, exists := allFns[callee.String()]; exists {
							addEntry(callee)
						}
					}
				}
				// Deferred calls.
				if deferInstr, ok := instr.(*ssa.Defer); ok {
					callee := deferInstr.Common().StaticCallee()
					if callee != nil {
						if _, exists := allFns[callee.String()]; exists {
							addEntry(callee)
						}
					}
				}
			}
		}
	}

	// Find dead functions.
	var findings []Finding
	var deadFns []*ssa.Function
	for key, fn := range allFns {
		if !reachable[key] {
			deadFns = append(deadFns, fn)
		}
	}

	sort.Slice(deadFns, func(i, j int) bool {
		return deadFns[i].Pos() < deadFns[j].Pos()
	})

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

	return findings, nil
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

var _ = token.NoPos
var _ = callgraph.New

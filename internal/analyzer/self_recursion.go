package analyzer

import (
	"fmt"
	"go/ast"
	"sort"
)

// selfRecursionAnalyzer flags functions that immediately call themselves before
// any base-case guard can run. Intentional recursion deeper in conditionals or
// loops is allowed; this catches accidental wrappers like f(){ return f() }.
type selfRecursionAnalyzer struct{}

func newSelfRecursionAnalyzer() *selfRecursionAnalyzer { return &selfRecursionAnalyzer{} }

func (a *selfRecursionAnalyzer) Name() string       { return "self-recursion" }
func (a *selfRecursionAnalyzer) Category() Category { return CategoryCodeSmell }
func (a *selfRecursionAnalyzer) Description() string {
	return "Functions that immediately recurse into themselves"
}

func (a *selfRecursionAnalyzer) Analyze(ctx *Context) ([]Finding, error) {
	var findings []Finding
	for _, files := range ctx.SyntaxByPkg {
		for _, file := range files {
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil || len(fn.Body.List) == 0 {
					continue
				}
				call := immediateSelfCall(fn)
				if call == nil {
					continue
				}
				pos := ctx.FSET.Position(call.Pos())
				findings = append(findings, Finding{
					Analyzer:   a.Name(),
					Category:   a.Category(),
					Severity:   SeverityCritical,
					Message:    fmt.Sprintf("%s immediately calls itself", funcLabel(fn)),
					Detail:     "The first executable statement calls the same function before any guard, delegation, or base case can run.",
					File:       pos.Filename,
					Line:       pos.Line,
					RuleID:     "GLW-SR001",
					Suggestion: "Agent fix: replace the recursive call with the intended helper, field access, or delegated receiver. If recursion is intentional, move it behind an explicit base-case guard.",
				})
			}
		}
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].File != findings[j].File {
			return findings[i].File < findings[j].File
		}
		return findings[i].Line < findings[j].Line
	})
	return findings, nil
}

func immediateSelfCall(fn *ast.FuncDecl) *ast.CallExpr {
	stmt := fn.Body.List[0]
	switch s := stmt.(type) {
	case *ast.ReturnStmt:
		for _, result := range s.Results {
			if call, ok := result.(*ast.CallExpr); ok && isSelfCall(fn, call) {
				return call
			}
		}
	case *ast.AssignStmt:
		for _, rhs := range s.Rhs {
			if call, ok := rhs.(*ast.CallExpr); ok && isSelfCall(fn, call) {
				return call
			}
		}
	case *ast.ExprStmt:
		if call, ok := s.X.(*ast.CallExpr); ok && isSelfCall(fn, call) {
			return call
		}
	}
	return nil
}

func isSelfCall(fn *ast.FuncDecl, call *ast.CallExpr) bool {
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		return fn.Recv == nil && fun.Name == fn.Name.Name
	case *ast.SelectorExpr:
		return fun.Sel.Name == fn.Name.Name && selectorUsesReceiver(fn, fun)
	}
	return false
}

func selectorUsesReceiver(fn *ast.FuncDecl, sel *ast.SelectorExpr) bool {
	if fn.Recv == nil || len(fn.Recv.List) == 0 || len(fn.Recv.List[0].Names) == 0 {
		return false
	}
	recv := fn.Recv.List[0].Names[0].Name
	if recv == "" {
		return false
	}
	ident, ok := sel.X.(*ast.Ident)
	return ok && ident.Name == recv
}

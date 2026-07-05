package analyzer

import (
	"fmt"
	"go/ast"
	"sort"
)

// thinWrapperAnalyzer flags functions that just delegate to a single other
// call — the Go equivalent of Fallow's thin_wrapper. These add indirection
// without value.
type thinWrapperAnalyzer struct{}

func newThinWrapperAnalyzer() *thinWrapperAnalyzer { return &thinWrapperAnalyzer{} }

func (a *thinWrapperAnalyzer) Name() string        { return "thin-wrappers" }
func (a *thinWrapperAnalyzer) Category() Category  { return CategoryCodeSmell }
func (a *thinWrapperAnalyzer) Description() string { return "Functions that just delegate to a single call (thin wrappers)" }

func (a *thinWrapperAnalyzer) Analyze(ctx *Context) ([]Finding, error) {
	fns := a.collectFunctions(ctx)
	findings := a.checkThinWrappers(ctx, fns)

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].File != findings[j].File {
			return findings[i].File < findings[j].File
		}
		return findings[i].Line < findings[j].Line
	})
	return findings, nil
}

// collectFunctions gathers all function declarations with 1–3 statements
// in their body (candidates for thin wrapper detection).
func (a *thinWrapperAnalyzer) collectFunctions(ctx *Context) []*ast.FuncDecl {
	var fns []*ast.FuncDecl
	for _, files := range ctx.SyntaxByPkg {
		for _, file := range files {
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				// Skip very short functions (< 3 statements).
				stmts := fn.Body.List
				if len(stmts) < 1 || len(stmts) > 3 {
					continue
				}
				fns = append(fns, fn)
			}
		}
	}
	return fns
}

// checkThinWrappers examines collected functions and flags those that are
// thin wrappers around a single call.
func (a *thinWrapperAnalyzer) checkThinWrappers(ctx *Context, fns []*ast.FuncDecl) []Finding {
	var findings []Finding
	for _, fn := range fns {
		if wrappedCall, ok := detectThinWrapper(fn.Body.List); ok && wrappedCall != "" {
			findings = append(findings, a.createThinWrapperFinding(ctx, fn, wrappedCall))
		}
	}
	return findings
}

// detectThinWrapper checks whether a statement list represents a thin wrapper
// and returns the wrapped call name if so.
func detectThinWrapper(stmts []ast.Stmt) (string, bool) {
	if len(stmts) == 1 {
		return detectSingleStmtWrapper(stmts[0])
	}
	if len(stmts) == 2 {
		return detectCallPlusReturnWrapper(stmts)
	}
	return "", false
}

// detectSingleStmtWrapper checks a single statement for a wrapping call.
func detectSingleStmtWrapper(stmt ast.Stmt) (string, bool) {
	switch s := stmt.(type) {
	case *ast.ReturnStmt:
		if len(s.Results) == 1 {
			if call, ok := s.Results[0].(*ast.CallExpr); ok {
				return callExprName(call), true
			}
		}
	case *ast.ExprStmt:
		if call, ok := s.X.(*ast.CallExpr); ok {
			return callExprName(call), true
		}
	}
	return "", false
}

// detectCallPlusReturnWrapper checks a 2-statement body: call + return.
func detectCallPlusReturnWrapper(stmts []ast.Stmt) (string, bool) {
	exprStmt, ok := stmts[0].(*ast.ExprStmt)
	if !ok {
		return "", false
	}
	ret, ok := stmts[1].(*ast.ReturnStmt)
	if !ok {
		return "", false
	}
	if len(ret.Results) != 0 && !(len(ret.Results) == 1 && isIdent(ret.Results[0])) {
		return "", false
	}
	call, ok := exprStmt.X.(*ast.CallExpr)
	if !ok {
		return "", false
	}
	return callExprName(call), true
}

// createThinWrapperFinding builds a Finding for a single thin wrapper function.
func (a *thinWrapperAnalyzer) createThinWrapperFinding(ctx *Context, fn *ast.FuncDecl, wrappedCall string) Finding {
	pos := ctx.FSET.Position(fn.Pos())
	return Finding{
		Analyzer:   a.Name(),
		Category:   a.Category(),
		Severity:   SeverityHint,
		Message:     fmt.Sprintf("%s is a thin wrapper around %s", funcLabel(fn), wrappedCall),
		File:        pos.Filename,
		Line:        pos.Line,
		EndLine:     ctx.FSET.Position(fn.End()).Line,
		RuleID:      "GLW-TW001",
		Suggestion:  "Consider inlining the call or removing this wrapper if it adds no semantic value.",
	}
}

func callExprName(call *ast.CallExpr) string {
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		return fun.Name
	case *ast.SelectorExpr:
		if x, ok := fun.X.(*ast.Ident); ok {
			return x.Name + "." + fun.Sel.Name
		}
		return fun.Sel.Name
	}
	return "unknown"
}

func isIdent(expr ast.Expr) bool {
	_, ok := expr.(*ast.Ident)
	return ok
}

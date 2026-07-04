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
	var findings []Finding

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

				// Check if the body is a single return of a function call,
				// or a single expression statement that's a call.
				isThinWrapper := false
				wrappedCall := ""

				if len(stmts) == 1 {
					switch s := stmts[0].(type) {
					case *ast.ReturnStmt:
						if len(s.Results) == 1 {
							if call, ok := s.Results[0].(*ast.CallExpr); ok {
								isThinWrapper = true
								wrappedCall = callExprName(call)
							}
						}
					case *ast.ExprStmt:
						if call, ok := s.X.(*ast.CallExpr); ok {
							isThinWrapper = true
							wrappedCall = callExprName(call)
						}
					}
				}

				// Also check: function with a single call + return.
				if len(stmts) == 2 {
					if _, ok := stmts[0].(*ast.ExprStmt); ok {
						if ret, ok := stmts[1].(*ast.ReturnStmt); ok {
							if len(ret.Results) == 0 || (len(ret.Results) == 1 && isIdent(ret.Results[0])) {
								if call, ok := stmts[0].(*ast.ExprStmt).X.(*ast.CallExpr); ok {
									isThinWrapper = true
									wrappedCall = callExprName(call)
								}
							}
						}
					}
				}

				if isThinWrapper && wrappedCall != "" {
					pos := ctx.FSET.Position(fn.Pos())
					findings = append(findings, Finding{
						Analyzer:  a.Name(),
						Category:  a.Category(),
						Severity:  SeverityHint,
						Message:    fmt.Sprintf("%s is a thin wrapper around %s", funcLabel(fn), wrappedCall),
						File:       pos.Filename,
						Line:       pos.Line,
						EndLine:    ctx.FSET.Position(fn.End()).Line,
						RuleID:     "GLW-TW001",
						Suggestion: "Consider inlining the call or removing this wrapper if it adds no semantic value.",
					})
				}
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

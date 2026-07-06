package analyzer

import (
	"fmt"
	"go/ast"
	"sort"
	"strings"
)

// thinWrapperAnalyzer flags functions that just delegate to a single other
// call — the Go equivalent of Fallow's thin_wrapper. These add indirection
// without value.
type thinWrapperAnalyzer struct{}

func newThinWrapperAnalyzer() *thinWrapperAnalyzer { return &thinWrapperAnalyzer{} }

func (a *thinWrapperAnalyzer) Name() string       { return "thin-wrappers" }
func (a *thinWrapperAnalyzer) Category() Category { return CategoryCodeSmell }
func (a *thinWrapperAnalyzer) Description() string {
	return "Functions that just delegate to a single call (thin wrappers)"
}

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
// Skips cobra command constructors and their RunE closures,
// which are inherently thin wrappers by design.
// Also skips common Go patterns that are thin wrappers by design:
//   - Error predicates (IsXxx wrapping errors.Is/errors.As)
//   - Exported wrappers around unexported (Open → open, encapsulation)
//   - Logger interface implementations (Errorf, Warnf, Infof, Debugf)
//   - Row-to-struct converters (xxxFromGetRow → xxxFromScalars)
func (a *thinWrapperAnalyzer) collectFunctions(ctx *Context) []*ast.FuncDecl {
	var fns []*ast.FuncDecl
	for _, files := range ctx.SyntaxByPkg {
		for _, file := range files {
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				// Skip cobra command constructors — they build *cobra.Command
				// structs and their thin wrappers are by design.
				if isCobraConstructor(fn) {
					continue
				}
				// Skip error predicates (IsXxx wrapping errors.Is/As).
				if isErrorPredicate(fn) {
					continue
				}
				// Skip exported wrappers around unexported functions
				// (e.g., Open → open). This is standard Go encapsulation.
				if isExportedWrapperOfUnexported(fn) {
					continue
				}
				// Skip logger interface implementations.
				if isLoggerMethod(fn) {
					continue
				}
				// Skip row-to-struct converters (xxxFromYyyRow → xxxFromScalars)
				if isRowConverter(fn) {
					continue
				}
				// Skip factory/config helpers (DefaultXxx, newXxxWriter)
				if isFactoryOrConfig(fn) {
					continue
				}
				// Skip cobra subcommand constructors that delegate to a shared
				// constructor (e.g., newGroupsAnnounceOnlyCmd → newGroupsToggleCmd)
				if isCobraSubcommandConstructor(fn) {
					continue
				}
				// Skip default-parameter wrappers (sendTextMessage → sendTextMessageWithSender)
				if isDefaultParameterWrapper(fn) {
					continue
				}
				if bindsDefaultArgument(fn) {
					continue
				}
				// Skip semantic aliases (FileURI → String, canonicalJIDString → String)
				if isSemanticAlias(fn) {
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

// isErrorPredicate returns true if the function is named IsXxx/isXxx and its
// body is a single return of an errors.Is, errors.As, or other boolean
// predicate call.
func isErrorPredicate(fn *ast.FuncDecl) bool {
	name := fn.Name.Name
	// Match both IsXxx (exported) and isXxx (unexported) — Go convention
	// for boolean predicate functions.
	if !strings.HasPrefix(name, "Is") && !strings.HasPrefix(name, "is") {
		return false
	}
	if fn.Body == nil {
		return false
	}
	stmts := fn.Body.List
	if len(stmts) != 1 {
		return false
	}
	ret, ok := stmts[0].(*ast.ReturnStmt)
	if !ok || len(ret.Results) != 1 {
		return false
	}
	call, ok := ret.Results[0].(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	// errors.Is, errors.As
	if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "errors" {
		return sel.Sel.Name == "Is" || sel.Sel.Name == "As"
	}
	// term.IsTerminal and similar boolean predicates from third-party
	// packages — if the called function starts with "Is" and returns
	// a bool, this is a predicate wrapper.
	return strings.HasPrefix(sel.Sel.Name, "Is")
}

// isExportedWrapperOfUnexported returns true if the function is exported
// and its body delegates to an unexported function with the same base name
// (e.g., Open → open, ParseFoo → parseFoo).
func isExportedWrapperOfUnexported(fn *ast.FuncDecl) bool {
	if !fn.Name.IsExported() || fn.Body == nil {
		return false
	}
	exportedName := fn.Name.Name
	// Expected unexported version: lowercase first letter
	if len(exportedName) < 2 {
		return false
	}
	unexportedName := strings.ToLower(exportedName[:1]) + exportedName[1:]
	stmts := fn.Body.List
	if len(stmts) < 1 || len(stmts) > 2 {
		return false
	}
	// Check if the body calls a function with the unexported name
	for _, stmt := range stmts {
		ast.Inspect(stmt, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if ident, ok := call.Fun.(*ast.Ident); ok && ident.Name == unexportedName {
					return false
				}
			}
			return true
		})
	}
	// Re-check: does any call in the body match the unexported name?
	var found bool
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if ident, ok := call.Fun.(*ast.Ident); ok && ident.Name == unexportedName {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

// isLoggerMethod returns true if the function name matches common logger
// interface method names (Errorf, Warnf, Infof, Debugf, Error, Warn, Info,
// Debug, Fatal, Fatalf, Print, Printf, Println).
// Also matches emit/warning delegate methods (emitXxxWarning → emitWarning)
// which are semantic aliases for log/warning levels.
func isLoggerMethod(fn *ast.FuncDecl) bool {
	name := fn.Name.Name
	switch name {
	case "Errorf", "Warnf", "Infof", "Debugf", "Tracef",
		"Error", "Warn", "Info", "Debug", "Trace",
		"Fatal", "Fatalf", "Panic", "Panicf",
		"Print", "Printf", "Println":
		return true
	}
	// Match emit/warning delegate methods — functions whose name contains
	// "emit" or "warning" that delegate to another emit/warning function.
	// e.g., emitChatStateWarning → a.emitWarning
	if strings.Contains(strings.ToLower(name), "emit") ||
		strings.Contains(strings.ToLower(name), "warning") {
		if fn.Body == nil {
			return false
		}
		var foundEmit bool
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
					called := strings.ToLower(sel.Sel.Name)
					if strings.Contains(called, "emit") ||
						strings.Contains(called, "warning") ||
						strings.Contains(called, "warn") {
						foundEmit = true
						return false
					}
				}
			}
			return true
		})
		if foundEmit {
			return true
		}
	}
	return false
}

// isRowConverter returns true if the function name matches the pattern
// xxxFromYyyRow or xxxFromYyy (where Yyy is Get/Find/Before/After) and
// delegates to a xxxFromScalars function. This is a common database row
// conversion pattern.
func isRowConverter(fn *ast.FuncDecl) bool {
	name := fn.Name.Name
	// Check if name contains "From" and ends with "Row"
	if !strings.Contains(name, "From") {
		return false
	}
	// Check if body calls a function ending in "FromScalars"
	if fn.Body == nil {
		return false
	}
	var found bool
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if ident, ok := call.Fun.(*ast.Ident); ok {
				if strings.HasSuffix(ident.Name, "FromScalars") {
					found = true
					return false
				}
			}
		}
		return true
	})
	return found
}

// isFactoryOrConfig returns true if the function is a factory or config
// helper: DefaultXxx, newXxxWriter, newXxxTableWriter, etc.
func isFactoryOrConfig(fn *ast.FuncDecl) bool {
	name := fn.Name.Name
	// DefaultXxx pattern (e.g., DefaultConfigPath, DefaultAccountStore)
	if strings.HasPrefix(name, "Default") {
		return true
	}
	// newXxx pattern where body creates a struct or calls a constructor
	if strings.HasPrefix(name, "new") && fn.Body != nil {
		// Check if body contains a composite literal or a call to a "New" function
		var found bool
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if _, ok := n.(*ast.CompositeLit); ok {
				found = true
				return false
			}
			if call, ok := n.(*ast.CallExpr); ok {
				if ident, ok := call.Fun.(*ast.Ident); ok && strings.HasPrefix(ident.Name, "New") {
					found = true
					return false
				}
			}
			return true
		})
		if found {
			return true
		}
	}
	return false
}

// isCobraSubcommandConstructor returns true if the function name starts with
// "new" and ends with "Cmd" and its body delegates to another "newXxxCmd"
// function (e.g., newGroupsAnnounceOnlyCmd → newGroupsToggleCmd).
func isCobraSubcommandConstructor(fn *ast.FuncDecl) bool {
	name := fn.Name.Name
	if !strings.HasPrefix(name, "new") || !strings.HasSuffix(name, "Cmd") {
		return false
	}
	if fn.Body == nil {
		return false
	}
	// Check if body calls another function ending in "Cmd"
	var found bool
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if ident, ok := call.Fun.(*ast.Ident); ok {
				if strings.HasSuffix(ident.Name, "Cmd") && ident.Name != name {
					found = true
					return false
				}
			}
		}
		return true
	})
	return found
}

// isDefaultParameterWrapper returns true if the function is a wrapper that
// adds a default parameter to another function call — i.e., the wrapper name
// is a prefix of the wrapped function name (e.g., sendTextMessage wraps
// sendTextMessageWithSender, buildPollVoteInfo wraps buildPollVoteInfoForChats).
// This is a standard Go pattern for providing default arguments.
func isDefaultParameterWrapper(fn *ast.FuncDecl) bool {
	name := fn.Name.Name
	if fn.Body == nil {
		return false
	}
	// Find all called function names in the body
	var calledNames []string
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if ident, ok := call.Fun.(*ast.Ident); ok {
				calledNames = append(calledNames, ident.Name)
			}
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				calledNames = append(calledNames, sel.Sel.Name)
			}
		}
		return true
	})
	// Check if any called name has the wrapper name as a prefix
	for _, called := range calledNames {
		if called == name {
			continue
		}
		// e.g., sendTextMessage → sendTextMessageWithSender
		if strings.HasPrefix(called, name) && len(called) > len(name) {
			return true
		}
	}
	return false
}

func bindsDefaultArgument(fn *ast.FuncDecl) bool {
	params := parameterNames(fn)
	var found bool
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if found {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if _, ok := call.Fun.(*ast.Ident); !ok {
			return true
		}
		for _, arg := range call.Args {
			if isBoundDefaultArgument(arg, params) {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

func isBoundDefaultArgument(arg ast.Expr, params map[string]bool) bool {
	switch expr := arg.(type) {
	case *ast.Ident:
		return !params[expr.Name]
	case *ast.BasicLit:
		return true
	}
	return false
}

func parameterNames(fn *ast.FuncDecl) map[string]bool {
	params := make(map[string]bool)
	if fn.Type == nil || fn.Type.Params == nil {
		return params
	}
	for _, field := range fn.Type.Params.List {
		for _, name := range field.Names {
			params[name.Name] = true
		}
	}
	return params
}

// isSemanticAlias returns true if the function is a semantic alias — a
// wrapper that provides a more specific name for a general function
// (e.g., FileURI → String, canonicalJIDString → String,
// callLogMessageOutcome → cleanCallValue). These are intentional API design.
func isSemanticAlias(fn *ast.FuncDecl) bool {
	name := fn.Name.Name
	if fn.Body == nil {
		return false
	}
	// Find the primary called function name
	var calledName string
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if ident, ok := call.Fun.(*ast.Ident); ok && calledName == "" {
				calledName = ident.Name
			}
		}
		return true
	})
	if calledName == "" {
		return false
	}
	// If the wrapper name is longer/more specific than the called name,
	// it's likely a semantic alias
	if len(name) > len(calledName)+3 {
		return true
	}
	// If the called name is very generic (String, Clean, Format, etc.)
	switch calledName {
	case "String", "Clean", "Format", "Stringer", "Value":
		return true
	}
	return false
}

// isCobraConstructor returns true if the function body contains an actual
// cobra.Command struct literal. We do NOT match by name (newXxxCmd) because
// that pattern is too broad — only skip when we have concrete evidence of
// cobra usage in the function body.
func isCobraConstructor(fn *ast.FuncDecl) bool {
	if fn.Body == nil {
		return false
	}
	for _, stmt := range fn.Body.List {
		if containsCobraCommand(stmt) {
			return true
		}
	}
	return false
}

// containsCobraCommand checks if a statement contains a cobra.Command literal.
func containsCobraCommand(stmt ast.Stmt) bool {
	var found bool
	ast.Inspect(stmt, func(n ast.Node) bool {
		if found {
			return false
		}
		comp, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		if ident, ok := comp.Type.(*ast.SelectorExpr); ok {
			if pkg, ok := ident.X.(*ast.Ident); ok && pkg.Name == "cobra" && ident.Sel.Name == "Command" {
				found = true
				return false
			}
		}
		return true
	})
	return found
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
// Returns ("", false) if the call arguments contain function literals
// (closures) or nested calls, or if the call is a method call on a
// composite literal (struct construction) — those are composition, not
// thin wrappers.
func detectSingleStmtWrapper(stmt ast.Stmt) (string, bool) {
	switch s := stmt.(type) {
	case *ast.ReturnStmt:
		if len(s.Results) == 1 {
			if call, ok := s.Results[0].(*ast.CallExpr); ok {
				if hasComplexArgs(call) || isCallOnCompositeLiteral(call) {
					return "", false
				}
				if !isDirectFunctionCall(call) {
					return "", false
				}
				return callExprName(call), true
			}
		}
	case *ast.ExprStmt:
		if call, ok := s.X.(*ast.CallExpr); ok {
			if hasComplexArgs(call) || isCallOnCompositeLiteral(call) {
				return "", false
			}
			if !isDirectFunctionCall(call) {
				return "", false
			}
			return callExprName(call), true
		}
	}
	return "", false
}

// isCallOnCompositeLiteral returns true if the call is a method call on
// a composite literal (struct construction). For example:
//
//	(&url.URL{Scheme: "file", Path: path}).String()
//
// This is not a thin wrapper — the function constructs a value and calls
// a method on it, which is composition.
func isCallOnCompositeLiteral(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	return containsCompositeLiteral(sel.X)
}

// containsCompositeLiteral checks if an expression contains a composite
// literal (struct construction), unwrapping parentheses and unary
// operators as needed.
func containsCompositeLiteral(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.CompositeLit:
		return true
	case *ast.ParenExpr:
		return containsCompositeLiteral(e.X)
	case *ast.UnaryExpr:
		return containsCompositeLiteral(e.X)
	}
	return false
}

func isDirectFunctionCall(call *ast.CallExpr) bool {
	_, ok := call.Fun.(*ast.Ident)
	return ok
}

// hasComplexArgs returns true if any argument of the call is a function
// literal (closure) or a nested call expression. A function that wraps
// a call with complex arguments is composing operations, not thin-wrapping.
func hasComplexArgs(call *ast.CallExpr) bool {
	for _, arg := range call.Args {
		if hasNestedComplexity(arg) {
			return true
		}
	}
	return false
}

// hasNestedComplexity checks if an expression contains a function literal
// or a nested call expression.
func hasNestedComplexity(expr ast.Expr) bool {
	complex := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if complex {
			return false
		}
		switch n.(type) {
		case *ast.FuncLit:
			// Function literal (closure) as argument — not thin
			complex = true
			return false
		case *ast.CallExpr:
			// Nested call as argument — e.g., strings.ToLower(strings.TrimSpace(s))
			// This means the function is composing multiple operations.
			complex = true
			return false
		}
		return true
	})
	return complex
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
		Message:    fmt.Sprintf("%s is a thin wrapper around %s", funcLabel(fn), wrappedCall),
		File:       pos.Filename,
		Line:       pos.Line,
		EndLine:    ctx.FSET.Position(fn.End()).Line,
		RuleID:     "GLW-TW001",
		Suggestion: "Agent fix: inline this function at call sites, or keep it only if it adds validation, naming value, defaults, interface conformance, or a stable exported API boundary.",
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

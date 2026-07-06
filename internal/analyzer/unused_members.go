package analyzer

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"strings"
)

// unusedMembersAnalyzer finds unused struct fields and interface methods with no implementations.
type unusedMembersAnalyzer struct{}

func newUnusedMembersAnalyzer() *unusedMembersAnalyzer { return &unusedMembersAnalyzer{} }

func (a *unusedMembersAnalyzer) Name() string       { return "unused-members" }
func (a *unusedMembersAnalyzer) Category() Category { return CategoryUnused }
func (a *unusedMembersAnalyzer) Description() string {
	return "Finds unused struct fields and interface methods with no implementations"
}

func (a *unusedMembersAnalyzer) Analyze(ctx *Context) ([]Finding, error) {
	var findings []Finding
	findings = append(findings, a.checkUnusedFields(ctx)...)
	findings = append(findings, a.checkUnimplementedInterfaceMethods(ctx)...)
	return findings, nil
}

// checkUnusedFields finds struct fields that are never accessed.
func (a *unusedMembersAnalyzer) checkUnusedFields(ctx *Context) []Finding {
	return a.findUnusedFields(ctx, ctx.codeIndex().FieldUsage)
}

// fieldUsageKey builds the usage key for a selection, or returns "" if
// the selection is not a struct field access on a named type.
func fieldUsageKey(sel *types.Selection) string {
	recv := sel.Recv()
	if ptr, ok := recv.(*types.Pointer); ok {
		recv = ptr.Elem()
	}
	named, ok := recv.(*types.Named)
	if !ok {
		return ""
	}
	if named.Obj() == nil || named.Obj().Pkg() == nil {
		return ""
	}
	return named.Obj().Pkg().Path() + "." + named.Obj().Name() + "." + sel.Obj().Name()
}

// findUnusedFields checks all struct types for fields that are never accessed.
func (a *unusedMembersAnalyzer) findUnusedFields(ctx *Context, fieldUsage map[string]bool) []Finding {
	var findings []Finding
	for pkgPath, pkg := range ctx.TypesByPkg {
		scope := pkg.Scope()
		for _, name := range scope.Names() {
			obj := scope.Lookup(name)
			named, ok := obj.Type().(*types.Named)
			if !ok {
				continue
			}
			structType, ok := named.Underlying().(*types.Struct)
			if !ok {
				continue
			}
			if ctx.codeIndex().IsGeneratedObject(ctx, pkgPath, named.Obj()) {
				continue
			}
			findings = append(findings, a.checkStructFields(ctx, pkgPath, named, structType, fieldUsage)...)
		}
	}
	return findings
}

// checkStructFields checks each field of a single struct type for usage.
func (a *unusedMembersAnalyzer) checkStructFields(ctx *Context, pkgPath string, named *types.Named, structType *types.Struct, fieldUsage map[string]bool) []Finding {
	var findings []Finding
	for i := 0; i < structType.NumFields(); i++ {
		field := structType.Field(i)
		if field.Embedded() {
			continue
		}
		key := pkgPath + "." + named.Obj().Name() + "." + field.Name()
		if fieldUsage[key] || field.Exported() {
			continue
		}
		findings = append(findings, a.createUnusedFieldFinding(ctx, named, field))
	}
	return findings
}

// createUnusedFieldFinding builds a Finding for a single unused struct field.
func (a *unusedMembersAnalyzer) createUnusedFieldFinding(ctx *Context, named *types.Named, field *types.Var) Finding {
	pos := ctx.FSET.Position(field.Pos())
	return Finding{
		Analyzer:   a.Name(),
		Category:   CategoryUnused,
		Severity:   SeverityInfo,
		Message:    "struct field " + named.Obj().Name() + "." + field.Name() + " is never accessed",
		Detail:     "This field is not referenced anywhere in the codebase.",
		File:       pos.Filename,
		Line:       pos.Line,
		Suggestion: "Agent fix: remove the field if it is stale, or add the missing read/write path that should use it.",
		RuleID:     "GLW-UM001",
	}
}

// checkUnimplementedInterfaceMethods finds interface methods that have no
// concrete implementations.
func (a *unusedMembersAnalyzer) checkUnimplementedInterfaceMethods(ctx *Context) []Finding {
	var findings []Finding

	for _, pkg := range ctx.TypesByPkg {
		scope := pkg.Scope()
		for _, name := range scope.Names() {
			obj := scope.Lookup(name)
			named, ok := obj.Type().(*types.Named)
			if !ok {
				continue
			}
			iface, ok := named.Underlying().(*types.Interface)
			if !ok {
				continue
			}
			if ctx.codeIndex().IsGeneratedObject(ctx, pkg.Path(), named.Obj()) {
				continue
			}
			// Skip built-in interfaces (error, fmt.Stringer, etc.)
			// error is a predeclared type with Pkg() == nil
			if named.Obj().Pkg() == nil {
				continue
			}
			// Also skip interfaces from the universe scope
			if named.Obj().Pkg().Path() == "builtin" {
				continue
			}
			findings = append(findings, a.checkInterfaceMethods(ctx, named, iface)...)
		}
	}
	return findings
}

// checkInterfaceMethods checks each method of a single interface for
// implementations.
func (a *unusedMembersAnalyzer) checkInterfaceMethods(ctx *Context, named *types.Named, iface *types.Interface) []Finding {
	var findings []Finding
	for i := 0; i < iface.NumMethods(); i++ {
		method := iface.Method(i)
		implCount := countImplementations(ctx, method.Name())
		if implCount == 0 {
			findings = append(findings, a.createUnimplementedMethodFinding(ctx, named, method))
		}
	}
	return findings
}

// createUnimplementedMethodFinding builds a Finding for an interface method
// with no concrete implementations.
func (a *unusedMembersAnalyzer) createUnimplementedMethodFinding(ctx *Context, named *types.Named, method *types.Func) Finding {
	pos := ctx.FSET.Position(method.Pos())
	return Finding{
		Analyzer:   a.Name(),
		Category:   CategoryUnused,
		Severity:   SeverityInfo,
		Message:    "interface method " + named.Obj().Name() + "." + method.Name() + " has no implementations",
		Detail:     "No concrete type implements this method.",
		File:       pos.Filename,
		Line:       pos.Line,
		Suggestion: "Agent fix: remove this interface method, or add a concrete implementation with the exact method name and signature.",
		RuleID:     "GLW-UM002",
	}
}

func countImplementations(ctx *Context, methodName string) int {
	count := 0
	for _, pkg := range ctx.TypesByPkg {
		scope := pkg.Scope()
		for _, name := range scope.Names() {
			obj := scope.Lookup(name)
			named, ok := obj.Type().(*types.Named)
			if !ok {
				continue
			}
			if _, ok := named.Underlying().(*types.Interface); ok {
				continue
			}
			for i := 0; i < named.NumMethods(); i++ {
				if named.Method(i).Name() == methodName {
					count++
					break
				}
			}
		}
	}
	// If no implementation found in non-test code, scan test files in the
	// same directory for implementations. This is needed because the loader
	// doesn't load test files (Tests: false), but a test-only mock/fake
	// is a legitimate implementation — the interface isn't unused.
	if count == 0 {
		count += countTestImplementations(ctx, methodName)
	}
	return count
}

// countTestImplementations scans _test.go files adjacent to the interface
// definition for concrete types implementing the method. This uses a
// lightweight AST scan (no type checking) — we look for method declarations
// matching the method name in test files.
func countTestImplementations(ctx *Context, methodName string) int {
	// Collect all directories that contain Go source files.
	// For each directory, check if _test.go files exist and scan them.
	testDirs := make(map[string]bool)
	for _, files := range ctx.SyntaxByPkg {
		for _, file := range files {
			pos := ctx.FSET.Position(file.Pos())
			if pos.Filename == "" {
				continue
			}
			dir := filepath.Dir(pos.Filename)
			testDirs[dir] = true
		}
	}

	count := 0
	for dir := range testDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := entry.Name()
			if !strings.HasSuffix(name, "_test.go") {
				continue
			}
			path := filepath.Join(dir, name)
			count += scanTestFileForMethod(path, methodName)
		}
	}
	return count
}

// scanTestFileForMethod parses a test file and returns 1 if it contains a
// method declaration with the given method name.
func scanTestFileForMethod(path, methodName string) int {
	src, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, src, parser.ParseComments)
	if err != nil {
		return 0
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		// Must be a method (has receiver) — interface implementations
		// are always methods.
		if fn.Recv == nil || len(fn.Recv.List) == 0 {
			continue
		}
		if fn.Name.Name == methodName {
			return 1
		}
	}
	return 0
}

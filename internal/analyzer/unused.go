package analyzer

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"sort"
	"strings"
)

// unusedAnalyzer finds exported identifiers that are never used outside
// their own package.
type unusedAnalyzer struct{}

func newUnusedAnalyzer() *unusedAnalyzer { return &unusedAnalyzer{} }

func (a *unusedAnalyzer) Name() string       { return "unused" }
func (a *unusedAnalyzer) Category() Category { return CategoryUnused }
func (a *unusedAnalyzer) Description() string {
	return "Detects exported types, functions, variables, and constants that are never referenced outside their defining package"
}

// usage tracks an exported object and which packages reference it.
type usage struct {
	obj    types.Object
	usedBy map[string]bool // set of pkg paths that use it (other than own)
}

func (a *unusedAnalyzer) Analyze(ctx *Context) ([]Finding, error) {
	exportedObjs := a.collectExportedSymbols(ctx)
	a.checkExternalUsage(ctx, exportedObjs)
	return a.createUnusedFindings(ctx, exportedObjs), nil
}

// collectExportedSymbols builds a map of exported objects keyed by pkgPath.name.
func (a *unusedAnalyzer) collectExportedSymbols(ctx *Context) map[string]*usage {
	exportedObjs := make(map[string]*usage)
	index := ctx.codeIndex()
	for pkgPath, typPkg := range ctx.TypesByPkg {
		scope := typPkg.Scope()
		for _, name := range scope.Names() {
			obj := scope.Lookup(name)
			if obj == nil || !obj.Exported() {
				continue
			}
			// Skip main function in package main.
			if name == "main" && pkgPath == "main" {
				continue
			}
			if isBuildInjectedVar(ctx, pkgPath, obj) {
				continue
			}
			if index.IsGeneratedObject(ctx, pkgPath, obj) {
				continue
			}
			key := pkgPath + "." + name
			exportedObjs[key] = &usage{
				obj:    obj,
				usedBy: make(map[string]bool),
			}
		}
	}
	return exportedObjs
}

// checkExternalUsage scans all packages for references to exported objects
// from other packages.
func (a *unusedAnalyzer) checkExternalUsage(ctx *Context, exportedObjs map[string]*usage) {
	a.markIndexedUsage(ctx.codeIndex().ExportedUsage, exportedObjs)
	a.markSignatureAPIUsage(exportedObjs)
}

func (a *unusedAnalyzer) markIndexedUsage(symbolUsage map[string]map[string]bool, exportedObjs map[string]*usage) {
	for key, users := range symbolUsage {
		u, ok := exportedObjs[key]
		if !ok {
			continue
		}
		ownerPkg := objectPackagePath(u.obj)
		for usingPkg := range users {
			if ownerPkg == "" || usingPkg == ownerPkg {
				continue
			}
			u.usedBy[usingPkg] = true
		}
	}
}

func objectPackagePath(obj types.Object) string {
	if obj == nil || obj.Pkg() == nil {
		return ""
	}
	return obj.Pkg().Path()
}

// markSignatureAPIUsage treats exported types in the signature of an
// externally-used exported symbol as used. That keeps the analyzer strict about
// actual references while avoiding false positives for public return/parameter
// types such as NewReporter() Reporter or Load() *Config.
func (a *unusedAnalyzer) markSignatureAPIUsage(exportedObjs map[string]*usage) {
	changed := true
	for changed {
		changed = false
		for _, u := range exportedObjs {
			if len(u.usedBy) == 0 {
				continue
			}
			if a.markTypeReferences(u.obj.Type(), u.usedBy, exportedObjs) {
				changed = true
			}
		}
	}
}

func (a *unusedAnalyzer) markTypeReferences(t types.Type, usedBy map[string]bool, exportedObjs map[string]*usage) bool {
	switch typ := t.(type) {
	case *types.Basic:
		return false
	case *types.Named:
		return a.markNamedTypeReferences(typ, usedBy, exportedObjs)
	case *types.Pointer:
		return a.markTypeReferences(typ.Elem(), usedBy, exportedObjs)
	case *types.Slice:
		return a.markTypeReferences(typ.Elem(), usedBy, exportedObjs)
	case *types.Array:
		return a.markTypeReferences(typ.Elem(), usedBy, exportedObjs)
	case *types.Chan:
		return a.markTypeReferences(typ.Elem(), usedBy, exportedObjs)
	case *types.Map:
		return a.markPairTypeReferences(typ.Key(), typ.Elem(), usedBy, exportedObjs)
	case *types.Signature:
		return a.markSignatureTypeReferences(typ, usedBy, exportedObjs)
	case *types.Interface:
		return a.markInterfaceTypeReferences(typ, usedBy, exportedObjs)
	case *types.Struct:
		return a.markStructTypeReferences(typ, usedBy, exportedObjs)
	}
	return false
}

func (a *unusedAnalyzer) markNamedTypeReferences(typ *types.Named, usedBy map[string]bool, exportedObjs map[string]*usage) bool {
	changed := false
	if obj := typ.Obj(); obj != nil && obj.Exported() && obj.Pkg() != nil {
		key := obj.Pkg().Path() + "." + obj.Name()
		if u, ok := exportedObjs[key]; ok {
			changed = markUsageByPackages(u, usedBy)
		}
	}
	for i := 0; i < typ.TypeArgs().Len(); i++ {
		if a.markTypeReferences(typ.TypeArgs().At(i), usedBy, exportedObjs) {
			changed = true
		}
	}
	return changed
}

func markUsageByPackages(u *usage, usedBy map[string]bool) bool {
	changed := false
	for pkgPath := range usedBy {
		if !u.usedBy[pkgPath] {
			u.usedBy[pkgPath] = true
			changed = true
		}
	}
	return changed
}

func (a *unusedAnalyzer) markPairTypeReferences(left, right types.Type, usedBy map[string]bool, exportedObjs map[string]*usage) bool {
	changed := a.markTypeReferences(left, usedBy, exportedObjs)
	if a.markTypeReferences(right, usedBy, exportedObjs) {
		changed = true
	}
	return changed
}

func (a *unusedAnalyzer) markSignatureTypeReferences(typ *types.Signature, usedBy map[string]bool, exportedObjs map[string]*usage) bool {
	changed := a.markTupleReferences(typ.Params(), usedBy, exportedObjs)
	if a.markTupleReferences(typ.Results(), usedBy, exportedObjs) {
		changed = true
	}
	return changed
}

func (a *unusedAnalyzer) markInterfaceTypeReferences(typ *types.Interface, usedBy map[string]bool, exportedObjs map[string]*usage) bool {
	changed := false
	for i := 0; i < typ.NumMethods(); i++ {
		if a.markTypeReferences(typ.Method(i).Type(), usedBy, exportedObjs) {
			changed = true
		}
	}
	return changed
}

func (a *unusedAnalyzer) markStructTypeReferences(typ *types.Struct, usedBy map[string]bool, exportedObjs map[string]*usage) bool {
	changed := false
	for i := 0; i < typ.NumFields(); i++ {
		if a.markTypeReferences(typ.Field(i).Type(), usedBy, exportedObjs) {
			changed = true
		}
	}
	return changed
}

func (a *unusedAnalyzer) markTupleReferences(tuple *types.Tuple, usedBy map[string]bool, exportedObjs map[string]*usage) bool {
	if tuple == nil {
		return false
	}
	changed := false
	for i := 0; i < tuple.Len(); i++ {
		if a.markTypeReferences(tuple.At(i).Type(), usedBy, exportedObjs) {
			changed = true
		}
	}
	return changed
}

func isBuildInjectedVar(ctx *Context, pkgPath string, obj types.Object) bool {
	if _, ok := obj.(*types.Var); !ok {
		return false
	}
	for _, file := range ctx.SyntaxByPkg[pkgPath] {
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if ok && genDeclBuildInjectsObject(gen, obj) {
				return true
			}
		}
	}
	return false
}

func genDeclBuildInjectsObject(gen *ast.GenDecl, obj types.Object) bool {
	if gen.Tok != token.VAR {
		return false
	}
	for _, spec := range gen.Specs {
		valueSpec, ok := spec.(*ast.ValueSpec)
		if ok && valueSpecBuildInjectsObject(gen, valueSpec, obj) {
			return true
		}
	}
	return false
}

func valueSpecBuildInjectsObject(gen *ast.GenDecl, spec *ast.ValueSpec, obj types.Object) bool {
	for _, name := range spec.Names {
		if name.Pos() != obj.Pos() {
			continue
		}
		comment := gen.Doc.Text() + spec.Doc.Text() + spec.Comment.Text()
		return strings.Contains(comment, "-ldflags") || strings.Contains(comment, "-X ")
	}
	return false
}

// createUnusedFindings converts unused exported objects into Finding objects.
func (a *unusedAnalyzer) createUnusedFindings(ctx *Context, exportedObjs map[string]*usage) []Finding {
	var findings []Finding
	var unused []*usage
	for _, u := range exportedObjs {
		if len(u.usedBy) == 0 {
			unused = append(unused, u)
		}
	}

	// Sort by file:line.
	sort.Slice(unused, func(i, j int) bool {
		pi := ctx.FSET.Position(unused[i].obj.Pos())
		pj := ctx.FSET.Position(unused[j].obj.Pos())
		if pi.Filename != pj.Filename {
			return pi.Filename < pj.Filename
		}
		return pi.Line < pj.Line
	})

	for _, u := range unused {
		pos := ctx.FSET.Position(u.obj.Pos())
		findings = append(findings, Finding{
			Analyzer:   a.Name(),
			Category:   a.Category(),
			Severity:   SeverityHint,
			Message:    fmt.Sprintf("exported %s %q is not used outside its package", kindOf(u.obj), u.obj.Name()),
			File:       pos.Filename,
			Line:       pos.Line,
			RuleID:     "GLW-UU001",
			Suggestion: "Agent fix: unexport this symbol, remove it, or add a real external caller. Keep it exported only when it is part of a documented public API.",
		})
	}
	return findings
}

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

package analyzer

import (
	"fmt"
	"go/types"
	"sort"
)

// unusedAnalyzer finds exported identifiers that are never used outside
// their own package.
type unusedAnalyzer struct{}

func newUnusedAnalyzer() *unusedAnalyzer { return &unusedAnalyzer{} }

func (a *unusedAnalyzer) Name() string        { return "unused" }
func (a *unusedAnalyzer) Category() Category  { return CategoryUnused }
func (a *unusedAnalyzer) Description() string { return "Detects exported types, functions, variables, and constants that are never referenced outside their defining package" }

// usage tracks an exported object and which packages reference it.
type usage struct {
	obj     types.Object
	pkgPath string
	usedBy  map[string]bool // set of pkg paths that use it (other than own)
}

func (a *unusedAnalyzer) Analyze(ctx *Context) ([]Finding, error) {
	exportedObjs := a.collectExportedSymbols(ctx)
	a.checkExternalUsage(ctx, exportedObjs)
	return a.createUnusedFindings(ctx, exportedObjs), nil
}

// collectExportedSymbols builds a map of exported objects keyed by pkgPath.name.
func (a *unusedAnalyzer) collectExportedSymbols(ctx *Context) map[string]*usage {
	exportedObjs := make(map[string]*usage)
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
			key := pkgPath + "." + name
			exportedObjs[key] = &usage{
				obj:     obj,
				pkgPath: pkgPath,
				usedBy:  make(map[string]bool),
			}
		}
	}
	return exportedObjs
}

// checkExternalUsage scans all packages for references to exported objects
// from other packages.
func (a *unusedAnalyzer) checkExternalUsage(ctx *Context, exportedObjs map[string]*usage) {
	a.markImportedPackageSymbols(ctx, exportedObjs)
	a.markTypeUsageSymbols(ctx, exportedObjs)
}

// markImportedPackageSymbols marks all exported objects of a package as used
// when another target package imports it.
func (a *unusedAnalyzer) markImportedPackageSymbols(ctx *Context, exportedObjs map[string]*usage) {
	for pkgPath, typPkg := range ctx.TypesByPkg {
		for _, imported := range typPkg.Imports() {
			importPath := imported.Path()
			if _, isOurs := ctx.TypesByPkg[importPath]; !isOurs {
				continue
			}
			// This package imports one of our target packages.
			// Mark all exported objects of the imported package as used.
			for _, u := range exportedObjs {
				if u.pkgPath == importPath {
					u.usedBy[pkgPath] = true
				}
			}
		}
	}
}

// markTypeUsageSymbols scans types.Info.Uses for external references to
// exported objects.
func (a *unusedAnalyzer) markTypeUsageSymbols(ctx *Context, exportedObjs map[string]*usage) {
	for _, pkg := range ctx.Packages {
		if pkg.TypesInfo == nil {
			continue
		}
		usingPkgPath := pkg.PkgPath
		for _, obj := range pkg.TypesInfo.Uses {
			if obj == nil || !obj.Exported() {
				continue
			}
			ownerPkg := obj.Pkg()
			if ownerPkg == nil || ownerPkg.Path() == usingPkgPath {
				continue
			}
			key := ownerPkg.Path() + "." + obj.Name()
			if u, ok := exportedObjs[key]; ok {
				u.usedBy[usingPkgPath] = true
			}
		}
	}
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
			Analyzer: a.Name(),
			Category: a.Category(),
			Severity: SeverityHint,
			Message:   fmt.Sprintf("exported %s %q is not used outside its package", kindOf(u.obj), u.obj.Name()),
			File:      pos.Filename,
			Line:      pos.Line,
			RuleID:    "GLW-UU001",
			Suggestion: "Consider unexporting if this is internal, or document the external API contract. If used via reflection, add //gollaw:keep.",
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

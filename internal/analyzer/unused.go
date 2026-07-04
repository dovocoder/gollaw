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

func (a *unusedAnalyzer) Analyze(ctx *Context) ([]Finding, error) {
	// Build a usage map: for each exported object, track how many packages
	// reference it (excluding its own package).
	type usage struct {
		obj     types.Object
		pkgPath string
		usedBy  map[string]bool // set of pkg paths that use it (other than own)
	}

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

	// Scan all packages for references to exported objects.
	for pkgPath, typPkg := range ctx.TypesByPkg {
		// Check imports of this package.
		for _, imported := range typPkg.Imports() {
			importPath := imported.Path()
			if _, isOurs := ctx.TypesByPkg[importPath]; !isOurs {
				continue
			}
			// This package imports one of our target packages.
			// Mark all exported objects of the imported package as used.
			for key, u := range exportedObjs {
				if u.pkgPath == importPath {
					u.usedBy[pkgPath] = true
					_ = key
				}
			}
		}
	}

	// Also scan uses via types.Info — look at each package's uses map.
	for _, pkg := range ctx.Packages {
		if pkg.TypesInfo == nil {
			continue
		}
		usingPkgPath := pkg.PkgPath
		for ident, obj := range pkg.TypesInfo.Uses {
			if obj == nil || !obj.Exported() {
				continue
			}
			ownerPkg := obj.Pkg()
			if ownerPkg == nil {
				continue
			}
			ownerPath := ownerPkg.Path()
			if ownerPath == usingPkgPath {
				continue // same package, not an external use
			}
			key := ownerPath + "." + obj.Name()
			if u, ok := exportedObjs[key]; ok {
				u.usedBy[usingPkgPath] = true
			}
			_ = ident
		}
	}

	// Find unused exported objects.
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

	return findings, nil
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

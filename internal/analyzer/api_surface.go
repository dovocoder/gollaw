package analyzer

import (
	"go/types"
	"strings"
)

// apiSurfaceAnalyzer tracks which exported symbols form the intentional API surface vs accidental exports.
type apiSurfaceAnalyzer struct{}

func newAPISurfaceAnalyzer() *apiSurfaceAnalyzer { return &apiSurfaceAnalyzer{} }

func (a *apiSurfaceAnalyzer) Name() string        { return "api-surface" }
func (a *apiSurfaceAnalyzer) Category() Category   { return CategoryUnused }
func (a *apiSurfaceAnalyzer) Description() string  { return "Tracks intentional public API vs accidental exports" }

func (a *apiSurfaceAnalyzer) Analyze(ctx *Context) ([]Finding, error) {
	symbolUsage := a.collectSymbolUsage(ctx)
	return a.checkAccidentalExports(ctx, symbolUsage), nil
}

// collectSymbolUsage builds a map of exported symbol keys to the set of
// packages that reference them.
func (a *apiSurfaceAnalyzer) collectSymbolUsage(ctx *Context) map[string]map[string]bool {
	symbolUsage := make(map[string]map[string]bool)
	for _, pkg := range ctx.Packages {
		if pkg.TypesInfo == nil {
			continue
		}
		usingPkg := pkg.PkgPath
		for _, obj := range pkg.TypesInfo.Uses {
			ownerPkg, name, ok := extractSymbolInfo(obj)
			if !ok || !obj.Exported() {
				continue
			}
			key := ownerPkg + "." + name
			if symbolUsage[key] == nil {
				symbolUsage[key] = make(map[string]bool)
			}
			symbolUsage[key][usingPkg] = true
		}
	}
	return symbolUsage
}

// extractSymbolInfo returns (ownerPkg, name, ok) for a types.Object if it
// is a Func, TypeName, Const, or non-field Var with a package.
func extractSymbolInfo(obj types.Object) (ownerPkg, name string, ok bool) {
	switch v := obj.(type) {
	case *types.Func:
		if v.Pkg() == nil {
			return "", "", false
		}
		return v.Pkg().Path(), v.Name(), true
	case *types.TypeName:
		if v.Pkg() == nil {
			return "", "", false
		}
		return v.Pkg().Path(), v.Name(), true
	case *types.Const:
		if v.Pkg() == nil {
			return "", "", false
		}
		return v.Pkg().Path(), v.Name(), true
	case *types.Var:
		if v.IsField() || v.Pkg() == nil {
			return "", "", false
		}
		return v.Pkg().Path(), v.Name(), true
	}
	return "", "", false
}

// checkAccidentalExports finds exported symbols that are only used within
// their own package (or not used at all).
func (a *apiSurfaceAnalyzer) checkAccidentalExports(ctx *Context, symbolUsage map[string]map[string]bool) []Finding {
	var findings []Finding
	for pkgPath, pkg := range ctx.TypesByPkg {
		scope := pkg.Scope()
		for _, name := range scope.Names() {
			obj := scope.Lookup(name)
			if !obj.Exported() {
				continue
			}
			if finding, ok := a.checkSymbolUsage(ctx, pkgPath, name, obj, symbolUsage); ok {
				findings = append(findings, finding)
			}
		}
	}
	return findings
}

// checkSymbolUsage checks a single exported symbol for accidental export status.
func (a *apiSurfaceAnalyzer) checkSymbolUsage(ctx *Context, pkgPath, name string, obj types.Object, symbolUsage map[string]map[string]bool) (Finding, bool) {
	key := pkgPath + "." + name
	users := symbolUsage[key]
	if len(users) > 1 {
		return Finding{}, false
	}
	if !isOnlyUsedByOwnPackage(users, pkgPath) {
		return Finding{}, false
	}
	if implementsInterface(obj, ctx) {
		return Finding{}, false
	}
	pos := ctx.FSET.Position(obj.Pos())
	if pos.Filename == "" {
		return Finding{}, false
	}
	// Skip generated files (sqlc, protoc, mockgen, etc.)
	if isGeneratedFile(pos.Filename) {
		return Finding{}, false
	}
	severity := SeverityInfo
	if len(users) == 0 {
		severity = SeverityWarning
	}
	return Finding{
		Analyzer:   a.Name(),
		Category:   CategoryUnused,
		Severity:   severity,
		Message:     "exported " + name + " is only used within its own package — consider unexporting",
		Detail:      "This exported symbol is not referenced by any external package.",
		File:        pos.Filename,
		Line:        pos.Line,
		Suggestion:  "Unexport the symbol (rename to lowercase) if it's not part of the public API",
		RuleID:      "GLW-AS001",
	}, true
}

// isGeneratedFile returns true if the file appears to be auto-generated.
func isGeneratedFile(filename string) bool {
	// Check for common generated file patterns in the path
	for _, pattern := range []string{"/storedb/", "/sqlc/", "/mock/", "/mocks/", "/generated/", "/gen/"} {
		if strings.Contains(filename, pattern) {
			return true
		}
	}
	// Could also check file content for "Code generated" comment,
	// but path-based check is sufficient for most cases.
	return false
}

// isOnlyUsedByOwnPackage returns true if the symbol is used only by its own
// package (or not used at all).
func isOnlyUsedByOwnPackage(users map[string]bool, pkgPath string) bool {
	for userPkg := range users {
		if userPkg != pkgPath {
			return false
		}
	}
	return true
}

func implementsInterface(obj types.Object, ctx *Context) bool {
	named, ok := obj.Type().(*types.Named)
	if !ok {
		return false
	}
	for _, pkg := range ctx.TypesByPkg {
		scope := pkg.Scope()
		for _, name := range scope.Names() {
			ifaceObj := scope.Lookup(name)
			iface, ok := ifaceObj.Type().Underlying().(*types.Interface)
			if !ok {
				continue
			}
			if types.Implements(named, iface) || types.Implements(types.NewPointer(named), iface) {
				return true
			}
		}
	}
	return false
}

package analyzer

import (
	"go/types"
	"strings"
)

// apiSurfaceAnalyzer tracks which exported symbols form the intentional API surface vs accidental exports.
type apiSurfaceAnalyzer struct{}

func newAPISurfaceAnalyzer() *apiSurfaceAnalyzer { return &apiSurfaceAnalyzer{} }

func (a *apiSurfaceAnalyzer) Name() string       { return "api-surface" }
func (a *apiSurfaceAnalyzer) Category() Category { return CategoryUnused }
func (a *apiSurfaceAnalyzer) Description() string {
	return "Tracks intentional public API vs accidental exports"
}

func (a *apiSurfaceAnalyzer) Analyze(ctx *Context) ([]Finding, error) {
	return a.checkAccidentalExports(ctx, ctx.codeIndex().ExportedUsage), nil
}

// checkAccidentalExports finds exported symbols that are only used within
// their own package (or not used at all).
func (a *apiSurfaceAnalyzer) checkAccidentalExports(ctx *Context, symbolUsage map[string]map[string]bool) []Finding {
	var findings []Finding
	for pkgPath, pkg := range ctx.TypesByPkg {
		if isInternalPackagePath(pkgPath) {
			continue
		}
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

func isInternalPackagePath(pkgPath string) bool {
	return strings.Contains(pkgPath, "/internal/")
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
	if ctx.codeIndex().IsGeneratedObject(ctx, pkgPath, obj) {
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
		Message:    "exported " + name + " is only used within its own package — consider unexporting",
		Detail:     "This exported symbol is not referenced by any external package.",
		File:       pos.Filename,
		Line:       pos.Line,
		Suggestion: "Agent fix: unexport this symbol if it is package-local, or add a real external caller or public API documentation if it is intentional.",
		RuleID:     "GLW-AS001",
	}, true
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

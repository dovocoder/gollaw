package analyzer

import (
	"go/types"
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
			var ownerPkg string
			var name string
			switch v := obj.(type) {
			case *types.Func:
				if v.Pkg() == nil {
					continue
				}
				ownerPkg = v.Pkg().Path()
				name = v.Name()
			case *types.TypeName:
				if v.Pkg() == nil {
					continue
				}
				ownerPkg = v.Pkg().Path()
				name = v.Name()
			case *types.Const:
				if v.Pkg() == nil {
					continue
				}
				ownerPkg = v.Pkg().Path()
				name = v.Name()
			case *types.Var:
				if v.IsField() || v.Pkg() == nil {
					continue
				}
				ownerPkg = v.Pkg().Path()
				name = v.Name()
			default:
				continue
			}
			if !obj.Exported() {
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
			key := pkgPath + "." + name
			users := symbolUsage[key]
			if len(users) <= 1 {
				accidental := true
				for userPkg := range users {
					if userPkg != pkgPath {
						accidental = false
						break
					}
				}
				if accidental {
					if implementsInterface(obj, ctx) {
						continue
					}
					pos := ctx.FSET.Position(obj.Pos())
					if pos.Filename == "" {
						continue
					}
					severity := SeverityInfo
					if len(users) == 0 {
						severity = SeverityWarning
					}
					findings = append(findings, Finding{
						Analyzer:  a.Name(),
						Category:  CategoryUnused,
						Severity:  severity,
						Message:    "exported " + name + " is only used within its own package — consider unexporting",
						Detail:     "This exported symbol is not referenced by any external package.",
						File:       pos.Filename,
						Line:       pos.Line,
						Suggestion: "Unexport the symbol (rename to lowercase) if it's not part of the public API",
						RuleID:     "GLW-AS001",
					})
				}
			}
		}
	}

	return findings
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

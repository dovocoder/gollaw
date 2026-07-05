package analyzer

import (
	"go/types"
)

// unusedMembersAnalyzer finds unused struct fields and interface methods with no implementations.
type unusedMembersAnalyzer struct{}

func newUnusedMembersAnalyzer() *unusedMembersAnalyzer { return &unusedMembersAnalyzer{} }

func (a *unusedMembersAnalyzer) Name() string        { return "unused-members" }
func (a *unusedMembersAnalyzer) Category() Category   { return CategoryUnused }
func (a *unusedMembersAnalyzer) Description() string   { return "Finds unused struct fields and interface methods with no implementations" }

func (a *unusedMembersAnalyzer) Analyze(ctx *Context) ([]Finding, error) {
	var findings []Finding
	findings = append(findings, a.checkUnusedFields(ctx)...)
	findings = append(findings, a.checkUnimplementedInterfaceMethods(ctx)...)
	return findings, nil
}

// checkUnusedFields finds struct fields that are never accessed.
func (a *unusedMembersAnalyzer) checkUnusedFields(ctx *Context) []Finding {
	var findings []Finding

	// Collect field usage.
	fieldUsage := make(map[string]bool)
	for _, pkg := range ctx.Packages {
		if pkg.TypesInfo == nil {
			continue
		}
		for _, sel := range pkg.TypesInfo.Selections {
			recv := sel.Recv()
			if named, ok := recv.(*types.Named); ok {
				if named.Obj() == nil || named.Obj().Pkg() == nil {
					continue
				}
				key := named.Obj().Pkg().Path() + "." + named.Obj().Name() + "." + sel.Obj().Name()
				fieldUsage[key] = true
			}
		}
	}

	// Check struct fields.
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
			for i := 0; i < structType.NumFields(); i++ {
				field := structType.Field(i)
				if field.Embedded() {
					continue
				}
				key := pkgPath + "." + named.Obj().Name() + "." + field.Name()
				if !fieldUsage[key] && !field.Exported() {
					pos := ctx.FSET.Position(field.Pos())
					if pos.Filename == "" {
						continue
					}
					findings = append(findings, Finding{
						Analyzer:  a.Name(),
						Category:  CategoryUnused,
						Severity:  SeverityInfo,
						Message:    "struct field " + named.Obj().Name() + "." + field.Name() + " is never accessed",
						Detail:     "This field is not referenced anywhere in the codebase.",
						File:       pos.Filename,
						Line:       pos.Line,
						Suggestion: "Remove the field or add a use for it",
						RuleID:     "GLW-UM001",
					})
				}
			}
		}
	}

	return findings
}

// checkUnimplementedInterfaceMethods finds interface methods that have no
// concrete implementations.
func (a *unusedMembersAnalyzer) checkUnimplementedInterfaceMethods(ctx *Context) []Finding {
	var findings []Finding

	// Check interface methods.
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
			for i := 0; i < iface.NumMethods(); i++ {
				method := iface.Method(i)
				implCount := countImplementations(ctx, method.Name())
				if implCount == 0 {
					pos := ctx.FSET.Position(method.Pos())
					if pos.Filename == "" {
						continue
					}
					findings = append(findings, Finding{
						Analyzer:  a.Name(),
						Category:  CategoryUnused,
						Severity:  SeverityInfo,
						Message:    "interface method " + named.Obj().Name() + "." + method.Name() + " has no implementations",
						Detail:     "No concrete type implements this method.",
						File:       pos.Filename,
						Line:       pos.Line,
						Suggestion: "Remove the method from the interface or add an implementation",
						RuleID:     "GLW-UM002",
					})
				}
			}
		}
	}

	return findings
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
	return count
}

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
	fieldUsage := collectFieldUsage(ctx)
	return a.findUnusedFields(ctx, fieldUsage)
}

// collectFieldUsage scans all type info selections to build a usage map
// keyed by pkgPath.typeName.fieldName.
func collectFieldUsage(ctx *Context) map[string]bool {
	fieldUsage := make(map[string]bool)
	for _, pkg := range ctx.Packages {
		if pkg.TypesInfo == nil {
			continue
		}
		for _, sel := range pkg.TypesInfo.Selections {
			key := fieldUsageKey(sel)
			if key != "" {
				fieldUsage[key] = true
			}
		}
	}
	return fieldUsage
}

// fieldUsageKey builds the usage key for a selection, or returns "" if
// the selection is not a struct field access on a named type.
//gollaw:keep
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
		Message:     "struct field " + named.Obj().Name() + "." + field.Name() + " is never accessed",
		Detail:      "This field is not referenced anywhere in the codebase.",
		File:        pos.Filename,
		Line:        pos.Line,
		Suggestion:  "Remove the field or add a use for it",
		RuleID:      "GLW-UM001",
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
		Message:     "interface method " + named.Obj().Name() + "." + method.Name() + " has no implementations",
		Detail:      "No concrete type implements this method.",
		File:        pos.Filename,
		Line:        pos.Line,
		Suggestion:  "Remove the method from the interface or add an implementation",
		RuleID:      "GLW-UM002",
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
	return count
}

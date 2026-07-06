package analyzer

import (
	"go/ast"
	"go/types"
	"strings"
)

// codeIndex holds derived facts that multiple analyzers need. Keeping these
// facts in one place makes analyzers stricter and less likely to drift apart.
type codeIndex struct {
	ExportedUsage map[string]map[string]bool
	FieldUsage    map[string]bool
	GeneratedFile map[string]bool
}

func (ctx *Context) codeIndex() *codeIndex {
	if ctx.index == nil {
		ctx.index = buildCodeIndex(ctx)
	}
	return ctx.index
}

func buildCodeIndex(ctx *Context) *codeIndex {
	return &codeIndex{
		ExportedUsage: collectExportedUsage(ctx),
		FieldUsage:    collectFieldUsageIndex(ctx),
		GeneratedFile: collectGeneratedFiles(ctx),
	}
}

func collectExportedUsage(ctx *Context) map[string]map[string]bool {
	symbolUsage := make(map[string]map[string]bool)
	for _, pkg := range ctx.Packages {
		if pkg.TypesInfo == nil {
			continue
		}
		for _, obj := range pkg.TypesInfo.Uses {
			key, ok := exportedObjectKey(obj)
			if !ok {
				continue
			}
			if symbolUsage[key] == nil {
				symbolUsage[key] = make(map[string]bool)
			}
			symbolUsage[key][pkg.PkgPath] = true
		}
	}
	return symbolUsage
}

func collectFieldUsageIndex(ctx *Context) map[string]bool {
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

func collectGeneratedFiles(ctx *Context) map[string]bool {
	generated := make(map[string]bool)
	for _, files := range ctx.SyntaxByPkg {
		for _, file := range files {
			filename := ctx.FSET.Position(file.Pos()).Filename
			if filename == "" {
				continue
			}
			generated[filename] = isGeneratedPath(filename) || fileHasGeneratedMarker(file)
		}
	}
	return generated
}

func exportedObjectKey(obj types.Object) (string, bool) {
	if obj == nil || !obj.Exported() {
		return "", false
	}
	ownerPkg, name, ok := objectOwnerAndName(obj)
	if !ok {
		return "", false
	}
	return ownerPkg + "." + name, true
}

func objectOwnerAndName(obj types.Object) (ownerPkg, name string, ok bool) {
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

func (idx *codeIndex) IsGeneratedFile(filename string) bool {
	if filename == "" {
		return false
	}
	if generated, ok := idx.GeneratedFile[filename]; ok {
		return generated
	}
	return isGeneratedPath(filename)
}

func (idx *codeIndex) IsGeneratedObject(ctx *Context, pkgPath string, obj types.Object) bool {
	if obj == nil {
		return false
	}
	pos := ctx.FSET.Position(obj.Pos())
	if idx.IsGeneratedFile(pos.Filename) {
		return true
	}
	for _, file := range ctx.SyntaxByPkg[pkgPath] {
		if file.Pos() <= obj.Pos() && obj.Pos() <= file.End() {
			return fileHasGeneratedMarker(file)
		}
	}
	return false
}

func isGeneratedPath(filename string) bool {
	for _, pattern := range []string{"/storedb/", "/sqlc/", "/mock/", "/mocks/", "/generated/", "/gen/"} {
		if strings.Contains(filename, pattern) {
			return true
		}
	}
	return false
}

func fileHasGeneratedMarker(file *ast.File) bool {
	for _, group := range file.Comments {
		if strings.Contains(group.Text(), "Code generated") && strings.Contains(group.Text(), "DO NOT EDIT") {
			return true
		}
	}
	return false
}

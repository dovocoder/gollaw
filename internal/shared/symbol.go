// Package shared provides common helpers used across multiple internal packages
// (explain, trace, etc.) to eliminate duplicated SSA symbol-matching logic.
package shared

import (
	"fmt"
	"go/types"
	"strings"

	"github.com/dovocoder/gollaw/internal/analyzer"
	"golang.org/x/tools/go/ssa"
)

// findFunction searches all SSA packages in the context for a function
// matching the given name. It checks package-level functions and methods on
// named types (both value and pointer receivers).
//gollaw:keep
func findFunction(ctx *analyzer.Context, name string) *ssa.Function {
	if ctx.SSA == nil {
		return nil
	}
	for _, ssaPkg := range ctx.SSAByPkg {
		if ssaPkg == nil {
			continue
		}
		for _, member := range ssaPkg.Members {
			if fn, ok := member.(*ssa.Function); ok {
				if matchFunctionName(fn, name) {
					return fn
				}
			}
			if typ, ok := member.(*ssa.Type); ok {
				ms := ssaPkg.Prog.MethodSets.MethodSet(typ.Type())
				for i := 0; i < ms.Len(); i++ {
					fn := ssaPkg.Prog.MethodValue(ms.At(i))
					if fn != nil && fn.Pkg == ssaPkg && matchFunctionName(fn, name) {
						return fn
					}
				}
				pointerType := types.NewPointer(typ.Type())
				ms2 := ssaPkg.Prog.MethodSets.MethodSet(pointerType)
				for i := 0; i < ms2.Len(); i++ {
					fn := ssaPkg.Prog.MethodValue(ms2.At(i))
					if fn != nil && fn.Pkg == ssaPkg && matchFunctionName(fn, name) {
						return fn
					}
				}
			}
		}
	}
	return nil
}

// matchFunctionName checks if an SSA function matches the requested symbol name.
// It matches against fn.Name(), fn.String(), "Type.Method", "pkg.func", and
// the last component of a dotted name.
//gollaw:keep
func matchFunctionName(fn *ssa.Function, name string) bool {
	if fn.Name() == name {
		return true
	}
	if fn.String() == name {
		return true
	}
	recv := fn.Signature.Recv()
	if recv != nil {
		typeName := recvTypeName(recv.Type())
		if typeName != "" {
			if typeName+"."+fn.Name() == name {
				return true
			}
		}
	}
	cleanName := cleanFuncName(fn)
	if cleanName == name {
		return true
	}
	parts := strings.Split(name, ".")
	if len(parts) > 0 && fn.Name() == parts[len(parts)-1] {
		if len(parts) >= 2 && recv != nil {
			if recvTypeName(recv.Type()) == parts[len(parts)-2] && fn.Name() == parts[len(parts)-1] {
				return true
			}
		}
		return true
	}
	return false
}

// cleanFuncName returns a readable "pkg.funcName" form.
//gollaw:keep
func cleanFuncName(fn *ssa.Function) string {
	if fn.Object() != nil && fn.Object().Pkg() != nil {
		return fmt.Sprintf("%s.%s", fn.Object().Pkg().Name(), fn.Name())
	}
	if fn.Pkg != nil {
		return fmt.Sprintf("%s.%s", fn.Pkg.Pkg.Name(), fn.Name())
	}
	return fn.String()
}

// funcLocation returns "file:line" for an SSA function.
//gollaw:keep
func funcLocation(ctx *analyzer.Context, fn *ssa.Function) string {
	pos := ctx.FSET.Position(fn.Pos())
	return fmt.Sprintf("%s:%d", pos.Filename, pos.Line)
}

// funcPackage returns the package path for a function.
//gollaw:keep
func funcPackage(fn *ssa.Function) string {
	if fn.Pkg != nil && fn.Pkg.Pkg != nil {
		return fn.Pkg.Pkg.Path()
	}
	if fn.Object() != nil && fn.Object().Pkg() != nil {
		return fn.Object().Pkg().Path()
	}
	return ""
}

// recvTypeName extracts the receiver type name, unwrapping pointers.
//gollaw:keep
func recvTypeName(t interface{}) string {
	if n, ok := t.(interface {
		Obj() interface{ Name() string }
	}); ok {
		return n.Obj().Name()
	}
	if p, ok := t.(interface {
		Elem() interface{}
	}); ok {
		return recvTypeName(p.Elem())
	}
	return ""
}

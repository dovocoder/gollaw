// Package ssalookup provides shared helpers for locating SSA functions by
// symbolic name. These helpers are used by both the trace and explain
// packages to resolve user-supplied symbol names (e.g. "pkg.Func",
// "Type.Method") to *ssa.Function values.
package ssalookup

import (
	"fmt"
	"go/types"
	"strings"

	"github.com/dovocoder/gollaw/internal/analyzer"
	"golang.org/x/tools/go/ssa"
)

// FindFunction searches all SSA packages for a function matching the given
// name. Matches against fn.Name(), fn.String(), "Type.Method", and "pkg.func".
func FindFunction(ctx *analyzer.Context, name string) *ssa.Function {
	if ctx.SSA == nil {
		return nil
	}
	for _, ssaPkg := range ctx.SSAByPkg {
		if ssaPkg == nil {
			continue
		}
		if fn := findFunctionInPackage(ssaPkg, name); fn != nil {
			return fn
		}
	}
	return nil
}

// findFunctionInPackage searches a single SSA package for a matching function.
func findFunctionInPackage(ssaPkg *ssa.Package, name string) *ssa.Function {
	for _, member := range ssaPkg.Members {
		if fn, ok := member.(*ssa.Function); ok {
			if matchFunctionName(fn, name) {
				return fn
			}
		}
		if typ, ok := member.(*ssa.Type); ok {
			if fn := findMethodOnType(ssaPkg, typ, name); fn != nil {
				return fn
			}
		}
	}
	return nil
}

// findMethodOnType searches for a method matching name on the given type
// and its pointer type.
func findMethodOnType(ssaPkg *ssa.Package, typ *ssa.Type, name string) *ssa.Function {
	if fn := findMethodInMethodSet(ssaPkg, typ.Type(), name); fn != nil {
		return fn
	}
	return findMethodInMethodSet(ssaPkg, types.NewPointer(typ.Type()), name)
}

// findMethodInMethodSet iterates the method set of recvType and returns the
// first method belonging to ssaPkg whose name matches. This is the shared
// helper extracted from the duplicated value-type/pointer-type loops that
// previously appeared inline in FindMethodOnType.
func findMethodInMethodSet(ssaPkg *ssa.Package, recvType types.Type, name string) *ssa.Function {
	ms := ssaPkg.Prog.MethodSets.MethodSet(recvType)
	for i := 0; i < ms.Len(); i++ {
		fn := ssaPkg.Prog.MethodValue(ms.At(i))
		if fn != nil && fn.Pkg == ssaPkg && matchFunctionName(fn, name) {
			return fn
		}
	}
	return nil
}

// matchFunctionName checks if an SSA function matches the requested symbol name.
func matchFunctionName(fn *ssa.Function, name string) bool {
	if fn.Name() == name || fn.String() == name {
		return true
	}
	recv := fn.Signature.Recv()
	typeName := ""
	if recv != nil {
		typeName = recvTypeName(recv.Type())
		if typeName != "" && typeName+"."+fn.Name() == name {
			return true
		}
	}
	if CleanFuncName(fn) == name {
		return true
	}
	return matchLastComponent(fn, name, recv, typeName)
}

// matchLastComponent checks if the last component of a dotted name matches.
func matchLastComponent(fn *ssa.Function, name string, recv *types.Var, typeName string) bool {
	parts := strings.Split(name, ".")
	if len(parts) == 0 || fn.Name() != parts[len(parts)-1] {
		return false
	}
	if len(parts) >= 2 && recv != nil {
		return typeName == parts[len(parts)-2]
	}
	return len(parts) < 2 || recv == nil
}

// CleanFuncName returns a readable "pkg.funcName" form.
func CleanFuncName(fn *ssa.Function) string {
	if fn.Object() != nil && fn.Object().Pkg() != nil {
		return fmt.Sprintf("%s.%s", fn.Object().Pkg().Name(), fn.Name())
	}
	if fn.Pkg != nil {
		return fmt.Sprintf("%s.%s", fn.Pkg.Pkg.Name(), fn.Name())
	}
	return fn.String()
}

// FuncPackage returns the package path for a function.
func FuncPackage(fn *ssa.Function) string {
	if fn.Pkg != nil && fn.Pkg.Pkg != nil {
		return fn.Pkg.Pkg.Path()
	}
	if fn.Object() != nil && fn.Object().Pkg() != nil {
		return fn.Object().Pkg().Path()
	}
	return ""
}

// FuncLocation returns "file:line" for an SSA function.
func FuncLocation(ctx *analyzer.Context, fn *ssa.Function) string {
	pos := ctx.FSET.Position(fn.Pos())
	return fmt.Sprintf("%s:%d", pos.Filename, pos.Line)
}

// recvTypeName extracts the receiver type name.
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

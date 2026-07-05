package loader

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// LoadConfig controls how the codebase is loaded.
type LoadConfig struct {
	// Patterns are Go package patterns (e.g. ./..., ./internal/...).
	Patterns []string
	// BuildFlags are passed to the Go build system.
	BuildFlags []string
	// Dir is the working directory. Empty = current directory.
	Dir string
}

// Result is the loaded codebase ready for analysis.
type Result struct {
	FSET     *token.FileSet
	Packages []*packages.Package
	SSA      *ssa.Program
	SSAByPkg map[string]*ssa.Package
	TypesByPkg map[string]*types.Package
	SyntaxByPkg map[string][]*ast.File
	// Errors encountered during loading (non-fatal).
	LoadErrors []error
	// Stats about the loaded codebase.
	Stats loadStats
}

// loadStats summarizes the loaded codebase.
type loadStats struct {
	PackageCount   int
	FileCount      int
	DeclCount      int
	FunctionCount  int
	TypeCount      int
}

// Load loads the codebase using go/packages and builds the SSA representation.
func Load(cfg LoadConfig) (*Result, error) {
	if len(cfg.Patterns) == 0 {
		cfg.Patterns = []string{"./..."}
	}
	pkgs, err := loadPackages(cfg)
	if err != nil {
		return nil, fmt.Errorf("load packages: %w", err)
	}
	result := &Result{
		Packages:    pkgs,
		SSAByPkg:    make(map[string]*ssa.Package),
		TypesByPkg:  make(map[string]*types.Package),
		SyntaxByPkg: make(map[string][]*ast.File),
	}
	result.FSET = resolveFSET(pkgs)
	for _, pkg := range pkgs {
		collectPkgStats(pkg, result)
	}
	buildSSA(result)
	return result, nil
}

// resolveFSET returns the FileSet shared by all packages, or a new one if none.
func resolveFSET(pkgs []*packages.Package) *token.FileSet {
	for _, pkg := range pkgs {
		if pkg.Fset != nil {
			return pkg.Fset
		}
	}
	return token.NewFileSet()
}

// collectPkgStats collects errors, indexes types/syntax, and accumulates stats.
func collectPkgStats(pkg *packages.Package, result *Result) {
	for _, e := range pkg.Errors {
		result.LoadErrors = append(result.LoadErrors, fmt.Errorf("pkg %s: %v", pkg.PkgPath, e))
	}
	if pkg.Types == nil || len(pkg.Syntax) == 0 {
		return
	}
	result.TypesByPkg[pkg.PkgPath] = pkg.Types
	result.SyntaxByPkg[pkg.PkgPath] = pkg.Syntax
	result.Stats.PackageCount++
	for _, f := range pkg.Syntax {
		result.Stats.FileCount++
		result.Stats.DeclCount += len(f.Decls)
		for _, decl := range f.Decls {
			if _, ok := decl.(*ast.FuncDecl); ok {
				result.Stats.FunctionCount++
			}
			if gen, ok := decl.(*ast.GenDecl); ok {
				for _, spec := range gen.Specs {
					if _, ok := spec.(*ast.TypeSpec); ok {
						result.Stats.TypeCount++
					}
				}
			}
		}
	}
}

// buildSSA builds the SSA representation for the whole program.
func buildSSA(result *Result) {
	prog, pkgsSSA := ssautil.AllPackages(result.Packages, ssa.InstantiateGenerics)
	if prog != nil {
		prog.Build()
		result.SSA = prog
		for _, p := range pkgsSSA {
			if p != nil {
				result.SSAByPkg[p.Pkg.Path()] = p
			}
		}
	}
}

func loadPackages(cfg LoadConfig) ([]*packages.Package, error) {
	pkgCfg := &packages.Config{
		Mode:       loadMode,
		Dir:        cfg.Dir,
		BuildFlags:  cfg.BuildFlags,
		Tests:      false,
	}
	pkgs, err := packages.Load(pkgCfg, cfg.Patterns...)
	if err != nil {
		return nil, err
	}
	// Filter out packages with no syntax or types (e.g. cgo failures).
	var valid []*packages.Package
	for _, p := range pkgs {
		if p.Types != nil && len(p.Syntax) > 0 {
			valid = append(valid, p)
		}
	}
	if len(valid) == 0 {
		return pkgs, nil // return all so caller can see errors
	}
	return valid, nil
}

const loadMode = packages.NeedName |
	packages.NeedFiles |
	packages.NeedCompiledGoFiles |
	packages.NeedImports |
	packages.NeedTypes |
	packages.NeedTypesSizes |
	packages.NeedSyntax |
	packages.NeedTypesInfo |
	packages.NeedDeps

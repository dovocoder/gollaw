package analyzer

import (
	"go/ast"
	"go/token"
	"go/types"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
)

// Context gives analyzers access to the loaded codebase.
type Context struct {
	FSET     *token.FileSet
	Packages []*packages.Package
	SSA      *ssa.Program
	// SSAByPkg maps package path → SSA package, for quick lookup.
	SSAByPkg map[string]*ssa.Package
	// TypesByPkg maps package path → *types.Package.
	TypesByPkg map[string]*types.Package
	// SyntaxByPkg maps package path → []*ast.File.
	SyntaxByPkg map[string][]*ast.File
	// Config holds user-provided options.
	Config Config
}

// Config configures the analysis run.
type Config struct {
	// Analyzers is the list of analyzer names to run. Empty = all.
	Analyzers []string
	// Rules are architecture rules.
	Rules []Rule
	// MinSeverity: findings below this are filtered.
	MinSeverity Severity
	// MaxComplexity threshold for the complexity analyzer.
	MaxCyclomatic  int
	MaxCognitive   int
	// MinDupLines: minimum duplicate block size.
	MinDupLines int
}

// Rule is an architecture boundary rule.
type Rule struct {
	Package    string // e.g. "internal/store"
	MustNotUse string // e.g. "internal/api"
}

// Analyzer is the interface every analyzer implements.
type Analyzer interface {
	Name() string
	Category() Category
	Description() string
	Analyze(ctx *Context) ([]Finding, error)
}

// Registry holds all available analyzers.
type Registry struct {
	analyzers []Analyzer
	byName    map[string]Analyzer
}

// NewRegistry creates a registry with all built-in analyzers.
func NewRegistry() *Registry {
	r := &Registry{byName: make(map[string]Analyzer)}
	r.Register(newDeadCodeAnalyzer())
	r.Register(newUnusedAnalyzer())
	r.Register(newComplexityAnalyzer())
	r.Register(newDuplicationAnalyzer())
	r.Register(newDependencyAnalyzer())
	r.Register(newArchitectureAnalyzer())
	r.Register(newUnusedDepsAnalyzer())
	r.Register(newLargeFunctionsAnalyzer())
	r.Register(newHotspotsAnalyzer())
	r.Register(newSecurityAnalyzer())
	r.Register(newNamingAnalyzer())
	r.Register(newUnusedFilesAnalyzer())
	r.Register(newThinWrapperAnalyzer())
	r.Register(newChurnAnalyzer())
	return r
}

// Register adds an analyzer to the registry.
func (r *Registry) Register(a Analyzer) {
	r.analyzers = append(r.analyzers, a)
	r.byName[a.Name()] = a
}

// Get returns an analyzer by name.
func (r *Registry) Get(name string) (Analyzer, bool) {
	a, ok := r.byName[name]
	return a, ok
}

// All returns every registered analyzer.
func (r *Registry) All() []Analyzer {
	return r.analyzers
}

// Select returns the analyzers matching the given names.
// If names is empty, all analyzers are returned.
func (r *Registry) Select(names []string) []Analyzer {
	if len(names) == 0 {
		return r.analyzers
	}
	var result []Analyzer
	for _, n := range names {
		if a, ok := r.byName[n]; ok {
			result = append(result, a)
		}
	}
	return result
}

// Names returns all analyzer names.
func (r *Registry) Names() []string {
	names := make([]string, len(r.analyzers))
	for i, a := range r.analyzers {
		names[i] = a.Name()
	}
	return names
}

package graph

import (
	"go/ast"
	"strings"

	"github.com/dovocoder/gollaw/internal/analyzer"
)

// ModuleGraph is the dependency graph of Go packages in a codebase.
//gollaw:ignore api-surface
type ModuleGraph struct {
	// Nodes holds one node per Go package, indexed by node ID.
	Nodes []moduleNode
	// Edges holds import relationships between packages.
	Edges []moduleEdge
	// reverseDeps maps a package path → node IDs of packages that import it (fan-in targets).
	reverseDeps map[string][]int
	// forwardDeps maps a package path → node IDs of packages it imports (fan-out targets).
	forwardDeps map[string][]int
	// pathIndex maps a package path → node ID for O(1) lookup.
	pathIndex map[string]int
}

// moduleNode represents a single Go package in the graph.
type moduleNode struct {
	Path         string
	Name         string
	Files        []string
	IsEntryPoint bool
	IsReachable  bool
}

// moduleEdge represents an import relationship from one package to another.
type moduleEdge struct {
	Source  int
	Target  int
	Imports []string
}

// BuildGraph constructs a ModuleGraph from the packages loaded in the analyzer context.
func BuildGraph(ctx *analyzer.Context) *ModuleGraph {
	g := &ModuleGraph{
		reverseDeps: make(map[string][]int),
		forwardDeps: make(map[string][]int),
		pathIndex:   make(map[string]int),
	}

	if ctx == nil {
		return g
	}

	buildNodes(ctx, g)
	buildEdges(ctx, g)

	return g
}

// buildNodes creates one node per package in the graph.
func buildNodes(ctx *analyzer.Context, g *ModuleGraph) {
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.PkgPath == "" {
			continue
		}
		if _, exists := g.pathIndex[pkg.PkgPath]; exists {
			continue
		}
		id := len(g.Nodes)
		node := moduleNode{
			Path: pkg.PkgPath,
			Name: pkg.Name,
		}
		if pkg.Name == "main" {
			node.IsEntryPoint = true
		}
		for _, f := range pkg.GoFiles {
			node.Files = append(node.Files, f)
		}
		g.Nodes = append(g.Nodes, node)
		g.pathIndex[pkg.PkgPath] = id
	}
}

// buildEdges creates import relationship edges between nodes.
func buildEdges(ctx *analyzer.Context, g *ModuleGraph) {
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.PkgPath == "" {
			continue
		}
		srcID, ok := g.pathIndex[pkg.PkgPath]
		if !ok {
			continue
		}
		importedSymbols := extractImportedSymbols(ctx, pkg.PkgPath)
		for impPath := range pkg.Imports {
			tgtID, ok := g.pathIndex[impPath]
			if !ok {
				continue
			}
			if srcID == tgtID {
				continue // skip self-edges
			}
			edge := moduleEdge{
				Source:  srcID,
				Target:  tgtID,
				Imports: importedSymbols[impPath],
			}
			g.Edges = append(g.Edges, edge)
			g.forwardDeps[pkg.PkgPath] = appendUniqueInt(g.forwardDeps[pkg.PkgPath], tgtID)
			g.reverseDeps[impPath] = appendUniqueInt(g.reverseDeps[impPath], srcID)
		}
	}
}

// NodeByPath returns the node ID for a package path, or -1 if not found.
func (g *ModuleGraph) NodeByPath(path string) int {
	if id, ok := g.pathIndex[path]; ok {
		return id
	}
	return -1
}

// ReverseDeps returns the node IDs of packages that import the given package.
func (g *ModuleGraph) ReverseDeps(path string) []int {
	return g.reverseDeps[path]
}

// ForwardDeps returns the node IDs of packages imported by the given package.
func (g *ModuleGraph) ForwardDeps(path string) []int {
	return g.forwardDeps[path]
}

// extractImportedSymbols builds a map of import-path → symbol names used from that import.
func extractImportedSymbols(ctx *analyzer.Context, pkgPath string) map[string][]string {
	result := make(map[string][]string)
	files, ok := ctx.SyntaxByPkg[pkgPath]
	if !ok {
		return result
	}
	for _, file := range files {
		for _, imp := range file.Imports {
			impPath := strings.Trim(imp.Path.Value, `"`)
			if imp.Name != nil {
				// aliased import — track the alias as a "symbol" so consumers can be found
				result[impPath] = appendUniqueString(result[impPath], imp.Name.Name)
			}
		}
		// Walk selector expressions to find qualified identifiers like pkg.Symbol.
		ast.Inspect(file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			ident, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			// Look up the import that this identifier corresponds to.
			obj := file.Scope.Lookup(ident.Name)
			if obj == nil {
				return true
			}
			// Object kind Import: the object's data is the import path.
			if impSpec, ok := obj.Decl.(*ast.ImportSpec); ok {
				impPath := strings.Trim(impSpec.Path.Value, `"`)
				result[impPath] = appendUniqueString(result[impPath], sel.Sel.Name)
			}
			return true
		})
	}
	return result
}

func appendUniqueInt(slice []int, v int) []int {
	for _, existing := range slice {
		if existing == v {
			return slice
		}
	}
	return append(slice, v)
}

func appendUniqueString(slice []string, v string) []string {
	for _, existing := range slice {
		if existing == v {
			return slice
		}
	}
	return append(slice, v)
}

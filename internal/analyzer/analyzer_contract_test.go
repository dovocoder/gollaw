package analyzer

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRegistryAnalyzerNamesAreUnique(t *testing.T) {
	seen := make(map[string]bool)
	for _, analyzer := range NewRegistry().All() {
		name := analyzer.Name()
		if name == "" {
			t.Fatalf("analyzer %T has empty name", analyzer)
		}
		if seen[name] {
			t.Fatalf("duplicate analyzer name %q", name)
		}
		seen[name] = true
	}
}

func TestAnalyzerFindingsHaveAgentFixSuggestions(t *testing.T) {
	fset := token.NewFileSet()
	files := parseAnalyzerSourceFiles(t, fset)
	for filename, file := range files {
		ast.Inspect(file, func(node ast.Node) bool {
			lit, ok := node.(*ast.CompositeLit)
			if !ok || !isFindingLiteral(lit) {
				return true
			}
			ruleID, suggestion := findingLiteralFields(lit)
			if ruleID == "" {
				return true
			}
			if !strings.HasPrefix(suggestion, "Agent fix:") {
				pos := fset.Position(lit.Pos())
				t.Fatalf("%s:%d finding %s suggestion must start with Agent fix:, got %q", filename, pos.Line, ruleID, suggestion)
			}
			return true
		})
	}
}

func parseAnalyzerSourceFiles(t *testing.T, fset *token.FileSet) map[string]*ast.File {
	t.Helper()
	files := make(map[string]*ast.File)
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read analyzer dir: %v", err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		files[filepath.Clean(name)] = file
	}
	return files
}

func isFindingLiteral(lit *ast.CompositeLit) bool {
	ident, ok := lit.Type.(*ast.Ident)
	return ok && ident.Name == "Finding"
}

func findingLiteralFields(lit *ast.CompositeLit) (ruleID, suggestion string) {
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok {
			continue
		}
		switch key.Name {
		case "RuleID":
			ruleID = staticStringPrefix(kv.Value)
		case "Suggestion":
			suggestion = staticStringPrefix(kv.Value)
		}
	}
	return ruleID, suggestion
}

func staticStringPrefix(expr ast.Expr) string {
	switch v := expr.(type) {
	case *ast.BasicLit:
		return strings.Trim(v.Value, "`\"")
	case *ast.BinaryExpr:
		return staticStringPrefix(v.X)
	case *ast.CallExpr:
		if len(v.Args) == 0 {
			return ""
		}
		return staticStringPrefix(v.Args[0])
	}
	return ""
}

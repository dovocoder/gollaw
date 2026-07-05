package analyzer

import (
	"fmt"
	"go/ast"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// unusedDepsAnalyzer checks go.mod dependencies against actual imports to find
// unused modules — the Go equivalent of Fallow's unused_deps.
type unusedDepsAnalyzer struct{}

func newUnusedDepsAnalyzer() *unusedDepsAnalyzer { return &unusedDepsAnalyzer{} }

func (a *unusedDepsAnalyzer) Name() string        { return "unused-deps" }
func (a *unusedDepsAnalyzer) Category() Category  { return CategoryUnused }
func (a *unusedDepsAnalyzer) Description() string { return "go.mod dependencies that are never imported" }

func (a *unusedDepsAnalyzer) Analyze(ctx *Context) ([]Finding, error) {
	goModPath, required, err := a.parseGoMod(ctx)
	if err != nil {
		return nil, err
	}
	if goModPath == "" {
		return nil, nil
	}

	imported := a.collectImportedModules(ctx)
	return a.findUnusedDependencies(goModPath, required, imported), nil
}

// parseGoMod locates and parses go.mod, returning the file path and a map of
// module path → version for all required modules.
func (a *unusedDepsAnalyzer) parseGoMod(ctx *Context) (string, map[string]string, error) {
	modDir := findModuleDirFromPackages(ctx)
	if modDir == "" {
		return "", nil, nil
	}

	goModPath := filepath.Join(modDir, "go.mod")
	content, err := os.ReadFile(goModPath)
	if err != nil {
		return "", nil, fmt.Errorf("read go.mod: %w", err)
	}

	required := parseRequireDirectives(string(content))
	return goModPath, required, nil
}

// findModuleDirFromPackages locates the module directory from loaded packages.
func findModuleDirFromPackages(ctx *Context) string {
	for _, pkg := range ctx.Packages {
		if len(pkg.GoFiles) > 0 {
			modDir := findGoModDir(filepath.Dir(pkg.GoFiles[0]))
			if modDir != "" {
				return modDir
			}
		}
	}
	return ""
}

// parseRequireDirectives extracts all require directives from go.mod content.
func parseRequireDirectives(content string) map[string]string {
	required := make(map[string]string)
	inRequireBlock := false
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		inRequireBlock = processRequireLine(line, inRequireBlock, required)
	}
	return required
}

// processRequireLine processes a single line of go.mod, updating the
// inRequireBlock state and the required map. Returns the new block state.
func processRequireLine(line string, inRequireBlock bool, required map[string]string) bool {
	if strings.HasPrefix(line, "require ") || strings.HasPrefix(line, "require\t") {
		rest := strings.TrimSpace(strings.TrimPrefix(line, "require"))
		if strings.HasPrefix(rest, "(") {
			return true
		}
		// Single-line require.
		parseRequireLine(rest, required)
		return inRequireBlock
	}

	if strings.HasPrefix(line, "(") {
		return inRequireBlock
	}
	if strings.HasPrefix(line, ")") {
		return false
	}

	if inRequireBlock {
		parseRequireLine(line, required)
	}
	return inRequireBlock
}

// collectImportedModules gathers all imported module paths from both AST
// imports and package-level imports.
func (a *unusedDepsAnalyzer) collectImportedModules(ctx *Context) map[string]bool {
	imported := make(map[string]bool)
	for _, files := range ctx.SyntaxByPkg {
		for _, file := range files {
			for _, imp := range file.Imports {
				path := strings.Trim(imp.Path.Value, `"`)
				// Skip stdlib (no dot in first segment).
				if !strings.Contains(path, ".") {
					continue
				}
				imported[path] = true
			}
		}
	}

	// Also check packages.Imports (includes dependencies of dependencies).
	for _, pkg := range ctx.Packages {
		for _, imp := range pkg.Imports {
			if imp == nil {
				continue
			}
			imported[imp.PkgPath] = true
		}
	}
	return imported
}

// findUnusedDependencies compares required modules against imported modules
// and returns findings for unused direct dependencies.
func (a *unusedDepsAnalyzer) findUnusedDependencies(goModPath string, required map[string]string, imported map[string]bool) []Finding {
	var findings []Finding
	// Sort module paths for deterministic output.
	var modPaths []string
	for modPath := range required {
		modPaths = append(modPaths, modPath)
	}
	sort.Strings(modPaths)

	for _, modPath := range modPaths {
		version := required[modPath]
		if isModuleUsed(modPath, imported) {
			continue
		}
		// Check if it's an indirect dependency — skip indirect deps.
		if strings.Contains(version, "// indirect") {
			continue
		}
		findings = append(findings, a.createUnusedDepFinding(goModPath, modPath, version))
	}
	return findings
}

// isModuleUsed checks whether a module path (or any sub-package) is imported.
func isModuleUsed(modPath string, imported map[string]bool) bool {
	if imported[modPath] {
		return true
	}
	prefix := modPath + "/"
	for impPath := range imported {
		if strings.HasPrefix(impPath, prefix) {
			return true
		}
	}
	return false
}

// createUnusedDepFinding builds a Finding for a single unused dependency.
func (a *unusedDepsAnalyzer) createUnusedDepFinding(goModPath, modPath, version string) Finding {
	return Finding{
		Analyzer:   a.Name(),
		Category:   a.Category(),
		Severity:   SeverityWarning,
		Message:     fmt.Sprintf("unused dependency %s %s", modPath, version),
		File:        goModPath,
		Line:        1,
		RuleID:      "GLW-UD001",
		Suggestion:  "Remove this dependency from go.mod or run `go mod tidy`.",
	}
}

func parseRequireLine(line string, required map[string]string) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "//") || strings.HasPrefix(line, "(") || strings.HasPrefix(line, ")") {
		return
	}
	// Format: module-path version [// indirect]
	parts := strings.Fields(line)
	if len(parts) >= 2 {
		required[parts[0]] = strings.Join(parts[1:], " ")
	}
}

func findGoModDir(dir string) string {
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return ""
}

var _ = ast.IsExported

package analyzer

import (
	"fmt"
	"go/ast"
	"os"
	"path/filepath"
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
	// Find go.mod from the first package's directory.
	var modDir string
	for _, pkg := range ctx.Packages {
		if len(pkg.GoFiles) > 0 {
			modDir = findGoModDir(filepath.Dir(pkg.GoFiles[0]))
			if modDir != "" {
				break
			}
		}
	}
	if modDir == "" {
		return nil, nil
	}

	goModPath := filepath.Join(modDir, "go.mod")
	content, err := os.ReadFile(goModPath)
	if err != nil {
		return nil, fmt.Errorf("read go.mod: %w", err)
	}

	// Parse require lines from go.mod.
	// go.mod format:
	//   require (
	//     example.com/foo v1.0.0
	//     example.com/bar v2.0.0 // indirect
	//   )
	// OR:
	//   require example.com/foo v1.0.0
	required := make(map[string]string) // module path → version
	inRequireBlock := false
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}

		if strings.HasPrefix(line, "require ") || strings.HasPrefix(line, "require	") {
			rest := strings.TrimSpace(strings.TrimPrefix(line, "require"))
			if strings.HasPrefix(rest, "(") {
				inRequireBlock = true
				continue
			}
			// Single-line require.
			parseRequireLine(rest, required)
			continue
		}

		if strings.HasPrefix(line, "(") {
			continue
		}
		if strings.HasPrefix(line, ")") {
			inRequireBlock = false
			continue
		}

		if inRequireBlock {
			parseRequireLine(line, required)
		}
	}

	// Collect all imported paths from packages.
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

	// Find unused dependencies. An import path matches a module if it
	// equals the module path OR is a subpackage (modulepath/subpath).
	isUsed := func(modPath string) bool {
		if imported[modPath] {
			return true
		}
		// Check subpackages: golang.org/x/tools/go/packages → module golang.org/x/tools
		prefix := modPath + "/"
		for impPath := range imported {
			if strings.HasPrefix(impPath, prefix) {
				return true
			}
		}
		return false
	}

	var findings []Finding
	for modPath, version := range required {
		if !isUsed(modPath) {
			// Check if it's an indirect dependency — skip indirect deps.
			if strings.Contains(version, "// indirect") {
				continue
			}
			findings = append(findings, Finding{
				Analyzer:   a.Name(),
				Category:   a.Category(),
				Severity:   SeverityWarning,
				Message:     fmt.Sprintf("unused dependency %s %s", modPath, version),
				File:        goModPath,
				Line:        1,
				RuleID:      "GLW-UD001",
				Suggestion:  "Remove this dependency from go.mod or run `go mod tidy`.",
			})
		}
	}

	return findings, nil
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

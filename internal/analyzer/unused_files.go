package analyzer

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// unusedFilesAnalyzer finds .go files that are never imported by any package
// in the codebase — the Go equivalent of Fallow's unused_files.
type unusedFilesAnalyzer struct{}

func newUnusedFilesAnalyzer() *unusedFilesAnalyzer { return &unusedFilesAnalyzer{} }

func (a *unusedFilesAnalyzer) Name() string        { return "unused-files" }
func (a *unusedFilesAnalyzer) Category() Category  { return CategoryUnused }
func (a *unusedFilesAnalyzer) Description() string { return "Go files that are not part of any loaded package" }

func (a *unusedFilesAnalyzer) Analyze(ctx *Context) ([]Finding, error) {
	// Collect all .go files known to the loaded packages.
	usedFiles := make(map[string]bool)
	for _, pkg := range ctx.Packages {
		for _, f := range pkg.GoFiles {
			usedFiles[absPath(f)] = true
		}
		for _, f := range pkg.CompiledGoFiles {
			usedFiles[absPath(f)] = true
		}
	}

	// Walk the module directory looking for orphaned .go files.
	var findings []Finding
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

	filepath.Walk(modDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			// Skip vendor, .git, etc.
			name := info.Name()
			if name == "vendor" || name == ".git" || name == "node_modules" || name == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		// Skip test files — they're always "used" if the package is.
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}

		abs := absPath(path)
		if !usedFiles[abs] {
			findings = append(findings, Finding{
				Analyzer:  a.Name(),
				Category:  a.Category(),
				Severity:  SeverityWarning,
				Message:    "orphaned Go file not part of any loaded package",
				File:       path,
				Line:       1,
				RuleID:     "GLW-UF001",
				Suggestion: "This file is not included in any package. Remove it, add a package declaration, or fix build tags.",
			})
		}
		return nil
	})

	sort.Slice(findings, func(i, j int) bool {
		return findings[i].File < findings[j].File
	})

	return findings, nil
}

func absPath(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	return abs
}

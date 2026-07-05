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
	usedFiles := collectUsedFiles(ctx)
	modDir := findModuleDir(ctx)
	if modDir == "" {
		return nil, nil
	}

	findings := a.findOrphanedFiles(modDir, usedFiles)

	sort.Slice(findings, func(i, j int) bool {
		return findings[i].File < findings[j].File
	})
	return findings, nil
}

// collectUsedFiles builds a set of all .go files known to loaded packages.
func collectUsedFiles(ctx *Context) map[string]bool {
	usedFiles := make(map[string]bool)
	for _, pkg := range ctx.Packages {
		for _, f := range pkg.GoFiles {
			usedFiles[absPath(f)] = true
		}
		for _, f := range pkg.CompiledGoFiles {
			usedFiles[absPath(f)] = true
		}
	}
	return usedFiles
}

// findModuleDir locates the module root directory from the loaded packages.
func findModuleDir(ctx *Context) string {
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

// findOrphanedFiles walks the module directory and returns findings for
// .go files not in the usedFiles set.
func (a *unusedFilesAnalyzer) findOrphanedFiles(modDir string, usedFiles map[string]bool) []Finding {
	var findings []Finding
	filepath.Walk(modDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if shouldSkipDir(info) {
			return filepath.SkipDir
		}
		if !info.IsDir() && shouldCheckFile(path) {
			abs := absPath(path)
			if !usedFiles[abs] {
				findings = append(findings, a.createOrphanedFileFinding(path))
			}
		}
		return nil
	})
	return findings
}

// shouldSkipDir returns true for directories that should be excluded from
// the walk (vendor, .git, node_modules, testdata).
func shouldSkipDir(info os.FileInfo) bool {
	if !info.IsDir() {
		return false
	}
	name := info.Name()
	return name == "vendor" || name == ".git" || name == "node_modules" || name == "testdata"
}

// shouldCheckFile returns true for non-test .go files that should be checked.
func shouldCheckFile(path string) bool {
	if !strings.HasSuffix(path, ".go") {
		return false
	}
	return !strings.HasSuffix(path, "_test.go")
}

// createOrphanedFileFinding builds a Finding for a single orphaned file.
func (a *unusedFilesAnalyzer) createOrphanedFileFinding(path string) Finding {
	return Finding{
		Analyzer:   a.Name(),
		Category:   a.Category(),
		Severity:   SeverityWarning,
		Message:     "orphaned Go file not part of any loaded package",
		File:        path,
		Line:        1,
		RuleID:      "GLW-UF001",
		Suggestion:  "This file is not included in any package. Remove it, add a package declaration, or fix build tags.",
	}
}

func absPath(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	return abs
}

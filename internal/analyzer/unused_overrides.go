package analyzer

import (
	"os"
	"path/filepath"
	"strings"
)

// unusedOverridesAnalyzer finds unused replace directives in go.mod.
type unusedOverridesAnalyzer struct{}

func newUnusedOverridesAnalyzer() *unusedOverridesAnalyzer { return &unusedOverridesAnalyzer{} }

func (a *unusedOverridesAnalyzer) Name() string        { return "unused-overrides" }
func (a *unusedOverridesAnalyzer) Category() Category   { return CategoryUnused }
func (a *unusedOverridesAnalyzer) Description() string   { return "Finds unused replace directives in go.mod" }

// replaceEntry holds a parsed replace directive's old path and source line.
type replaceEntry struct {
	oldPath string
	line    int
}

func (a *unusedOverridesAnalyzer) Analyze(ctx *Context) ([]Finding, error) {
	goModPath := findGoMod(ctx)
	if goModPath == "" {
		return nil, nil
	}

	data, err := os.ReadFile(goModPath)
	if err != nil {
		return nil, nil
	}

	replaces := parseReplaceDirectives(string(data))
	importedModules := collectImportedModulePaths(ctx)
	return a.findUnusedReplaces(goModPath, replaces, importedModules), nil
}

// parseReplaceDirectives extracts all replace directives from go.mod content.
func parseReplaceDirectives(content string) []replaceEntry {
	var replaces []replaceEntry
	lines := strings.Split(content, "\n")
	inReplaceBlock := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "replace (") {
			inReplaceBlock = true
			continue
		}
		if trimmed == ")" && inReplaceBlock {
			inReplaceBlock = false
			continue
		}
		if r, ok := parseReplaceLine(trimmed, i+1, inReplaceBlock); ok {
			replaces = append(replaces, r)
		}
	}
	return replaces
}

// parseReplaceLine parses a single replace directive line.
//gollaw:keep
func parseReplaceLine(trimmed string, lineNum int, inBlock bool) (replaceEntry, bool) {
	if strings.HasPrefix(trimmed, "replace ") {
		parts := strings.Fields(trimmed)
		if len(parts) >= 2 {
			return replaceEntry{oldPath: parts[1], line: lineNum}, true
		}
		return replaceEntry{}, false
	}
	if inBlock {
		parts := strings.Fields(trimmed)
		if len(parts) >= 2 {
			return replaceEntry{oldPath: parts[0], line: lineNum}, true
		}
	}
	return replaceEntry{}, false
}

// collectImportedModulePaths builds a set of all imported module paths.
func collectImportedModulePaths(ctx *Context) map[string]bool {
	importedModules := make(map[string]bool)
	for _, pkg := range ctx.Packages {
		for _, imp := range pkg.Imports {
			importedModules[imp.PkgPath] = true
		}
	}
	return importedModules
}

// findUnusedReplaces returns findings for replace directives whose modules
// are never imported by any package.
func (a *unusedOverridesAnalyzer) findUnusedReplaces(goModPath string, replaces []replaceEntry, importedModules map[string]bool) []Finding {
	var findings []Finding
	for _, r := range replaces {
		if importedModules[r.oldPath] {
			continue
		}
		if isModuleImportedAsPrefix(r.oldPath, importedModules) {
			continue
		}
		findings = append(findings, Finding{
			Analyzer:   a.Name(),
			Category:   CategoryUnused,
			Severity:   SeverityWarning,
			Message:     "replace directive for " + r.oldPath + " is unused (module not imported)",
			Detail:      "The module is not imported by any package in the codebase.",
			File:        goModPath,
			Line:        r.line,
			Suggestion:  "Remove the replace directive from go.mod",
			RuleID:      "GLW-UO001",
		})
	}
	return findings
}

// isModuleImportedAsPrefix checks whether any imported module has the given
// path as a prefix (e.g. sub-package imports).
func isModuleImportedAsPrefix(oldPath string, importedModules map[string]bool) bool {
	for imp := range importedModules {
		if strings.HasPrefix(imp, oldPath) {
			return true
		}
	}
	return false
}

func findGoMod(ctx *Context) string {
	for _, pkg := range ctx.Packages {
		if pkg.GoFiles == nil || len(pkg.GoFiles) == 0 {
			continue
		}
		dir := filepath.Dir(pkg.GoFiles[0])
		for i := 0; i < 10; i++ {
			goMod := filepath.Join(dir, "go.mod")
			if _, err := os.Stat(goMod); err == nil {
				return goMod
			}
			dir = filepath.Dir(dir)
		}
	}
	return ""
}

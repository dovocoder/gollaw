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

func (a *unusedOverridesAnalyzer) Analyze(ctx *Context) ([]Finding, error) {
	var findings []Finding

	goModPath := findGoMod(ctx)
	if goModPath == "" {
		return nil, nil
	}

	data, err := os.ReadFile(goModPath)
	if err != nil {
		return nil, nil
	}

	var replaces []struct {
		oldPath string
		line    int
	}
	lines := strings.Split(string(data), "\n")
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
		if strings.HasPrefix(trimmed, "replace ") {
			parts := strings.Fields(trimmed)
			if len(parts) >= 2 {
				replaces = append(replaces, struct {
					oldPath string
					line    int
				}{parts[1], i + 1})
			}
			continue
		}
		if inReplaceBlock {
			parts := strings.Fields(trimmed)
			if len(parts) >= 2 {
				replaces = append(replaces, struct {
					oldPath string
					line    int
				}{parts[0], i + 1})
			}
		}
	}

	importedModules := make(map[string]bool)
	for _, pkg := range ctx.Packages {
		for _, imp := range pkg.Imports {
			importedModules[imp.PkgPath] = true
		}
	}

	for _, r := range replaces {
		if !importedModules[r.oldPath] {
			used := false
			for imp := range importedModules {
				if strings.HasPrefix(imp, r.oldPath) {
					used = true
					break
				}
			}
			if !used {
				findings = append(findings, Finding{
					Analyzer:  a.Name(),
					Category:  CategoryUnused,
					Severity:  SeverityWarning,
					Message:    "replace directive for " + r.oldPath + " is unused (module not imported)",
					Detail:     "The module is not imported by any package in the codebase.",
					File:       goModPath,
					Line:       r.line,
					Suggestion: "Remove the replace directive from go.mod",
					RuleID:     "GLW-UO001",
				})
			}
		}
	}

	return findings, nil
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

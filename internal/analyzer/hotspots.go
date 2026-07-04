package analyzer

import (
	"fmt"
	"go/ast"
	"sort"
)

// hotspotsAnalyzer identifies files with high complexity density — the Go
// equivalent of Fallow's hotspots. A hotspot is a file where the ratio of
// total complexity to file size is unusually high, indicating a maintenance
// risk area.
type hotspotsAnalyzer struct{}

func newHotspotsAnalyzer() *hotspotsAnalyzer { return &hotspotsAnalyzer{} }

func (a *hotspotsAnalyzer) Name() string        { return "hotspots" }
func (a *hotspotsAnalyzer) Category() Category  { return CategoryComplexity }
func (a *hotspotsAnalyzer) Description() string { return "Files with high complexity density (maintenance risk areas)" }

func (a *hotspotsAnalyzer) Analyze(ctx *Context) ([]Finding, error) {
	type fileStats struct {
		file          string
		lineCount     int
		totalComplex  int
		funcCount     int
	}

	fileMap := make(map[string]*fileStats)

	for _, files := range ctx.SyntaxByPkg {
		for _, file := range files {
			start := ctx.FSET.Position(file.Package)
			end := ctx.FSET.Position(file.End())
			filePath := start.Filename

			stats, ok := fileMap[filePath]
			if !ok {
				stats = &fileStats{file: filePath}
				fileMap[filePath] = stats
			}
			stats.lineCount += end.Line - start.Line + 1

			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				stats.funcCount++
				stats.totalComplex += cyclomaticComplexity(fn)
			}
		}
	}

	var findings []Finding
	for _, stats := range fileMap {
		if stats.lineCount < 10 || stats.funcCount == 0 {
			continue
		}
		// Complexity density: total complexity / lines of code.
		density := float64(stats.totalComplex) / float64(stats.lineCount)
		// Average complexity per function.
		avgComplex := float64(stats.totalComplex) / float64(stats.funcCount)

		// Flag files with high density or high average complexity.
		if density > 0.5 || avgComplex > 10 {
			sev := SeverityInfo
			if density > 1.0 || avgComplex > 20 {
				sev = SeverityWarning
			}
			if density > 2.0 || avgComplex > 30 {
				sev = SeverityCritical
			}

			findings = append(findings, Finding{
				Analyzer:  a.Name(),
				Category:  a.Category(),
				Severity:  sev,
				Message:    fmt.Sprintf("complexity hotspot: %d functions, %d total complexity (%.1f avg, %.2f density)", stats.funcCount, stats.totalComplex, avgComplex, density),
				File:       stats.file,
				Line:       1,
				RuleID:     "GLW-HS001",
				Suggestion: "This file concentrates high complexity. Consider splitting it into smaller, focused files.",
			})
		}
	}

	sort.Slice(findings, func(i, j int) bool {
		return findings[i].File < findings[j].File
	})

	return findings, nil
}

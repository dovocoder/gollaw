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

func (a *hotspotsAnalyzer) Name() string       { return "hotspots" }
func (a *hotspotsAnalyzer) Category() Category { return CategoryComplexity }
func (a *hotspotsAnalyzer) Description() string {
	return "Files with high complexity density (maintenance risk areas)"
}

// fileStats collects complexity and line metrics per file.
type fileStats struct {
	file         string
	lineCount    int
	totalComplex int
	funcCount    int
}

func (a *hotspotsAnalyzer) Analyze(ctx *Context) ([]Finding, error) {
	fileMap := a.collectFileStats(ctx)
	findings := a.findHotspots(fileMap)

	sort.Slice(findings, func(i, j int) bool {
		return findings[i].File < findings[j].File
	})
	return findings, nil
}

// collectFileStats traverses all syntax trees and accumulates per-file
// complexity and line-count metrics.
func (a *hotspotsAnalyzer) collectFileStats(ctx *Context) map[string]*fileStats {
	fileMap := make(map[string]*fileStats)
	for _, files := range ctx.SyntaxByPkg {
		for _, file := range files {
			a.accumulateFileStats(ctx, file, fileMap)
		}
	}
	return fileMap
}

// accumulateFileStats adds line and complexity metrics for a single file
// into the fileMap.
func (a *hotspotsAnalyzer) accumulateFileStats(ctx *Context, file *ast.File, fileMap map[string]*fileStats) {
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

// findHotspots generates findings for files with high complexity density
// or high average complexity per function.
func (a *hotspotsAnalyzer) findHotspots(fileMap map[string]*fileStats) []Finding {
	var findings []Finding
	for _, stats := range fileMap {
		if stats.lineCount < 10 || stats.funcCount < 3 {
			continue
		}
		density := float64(stats.totalComplex) / float64(stats.lineCount)
		avgComplex := float64(stats.totalComplex) / float64(stats.funcCount)

		if density > 0.5 || avgComplex > 15 {
			findings = append(findings, a.createHotspotFinding(stats, density, avgComplex))
		}
	}
	return findings
}

// createHotspotFinding builds a finding for a single hotspot file.
func (a *hotspotsAnalyzer) createHotspotFinding(stats *fileStats, density, avgComplex float64) Finding {
	sev := hotspotSeverity(density, avgComplex)
	return Finding{
		Analyzer:   a.Name(),
		Category:   a.Category(),
		Severity:   sev,
		Message:    fmt.Sprintf("complexity hotspot: %d functions, %d total complexity (%.1f avg, %.2f density)", stats.funcCount, stats.totalComplex, avgComplex, density),
		File:       stats.file,
		Line:       1,
		RuleID:     "GLW-HS001",
		Suggestion: "This file concentrates high complexity. Consider splitting it into smaller, focused files.",
	}
}

// hotspotSeverity maps density and average complexity to a severity level.
func hotspotSeverity(density, avgComplex float64) Severity {
	switch {
	case density > 2.0 || avgComplex > 30:
		return SeverityCritical
	case density > 1.0 || avgComplex > 20:
		return SeverityWarning
	default:
		return SeverityInfo
	}
}

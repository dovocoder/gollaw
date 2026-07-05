// Package analysis provides a shared entry point for loading a Go codebase,
// running all registered analyzers, and collecting findings.
//
// It eliminates the duplicated "load codebase → build context → run analyzers"
// pattern that previously appeared in internal/cli, internal/mcp, internal/action,
// and internal/fix.
package analysis

import (
	"fmt"

	"github.com/dovocoder/gollaw/internal/analyzer"
	"github.com/dovocoder/gollaw/internal/loader"
	"github.com/dovocoder/gollaw/internal/reporter"
)

// Result holds the output of a full analysis run.
//gollaw:keep
type Result struct {
	Findings []analyzer.Finding
	Context  *analyzer.Context
	Stats    reporter.CodebaseStats
	Report   *reporter.Report
	// LoaderResult is the raw loader output (packages, SSA, etc.).
	LoaderResult *loader.Result
	// AnalyzerNames is the list of analyzers that were run.
	AnalyzerNames []string
}

// RunAnalysis loads the codebase at dir using the given patterns, builds the
// analyzer context, runs all registered analyzers, and returns the findings,
// context, stats, and a built report.
//
// If patterns is empty, ["./..."] is used.
// version is used in the report header (pass the CLI/application version).
//gollaw:keep
func RunAnalysis(dir string, patterns []string, version string) (*Result, error) {
	if len(patterns) == 0 {
		patterns = []string{"./..."}
	}

	result, err := loader.Load(loader.LoadConfig{
		Patterns: patterns,
		Dir:      dir,
	})
	if err != nil {
		return nil, fmt.Errorf("load codebase: %w", err)
	}

	ctx := &analyzer.Context{
		FSET:        result.FSET,
		Packages:    result.Packages,
		SSA:         result.SSA,
		SSAByPkg:    result.SSAByPkg,
		TypesByPkg:  result.TypesByPkg,
		SyntaxByPkg: result.SyntaxByPkg,
	}

	registry := analyzer.NewRegistry()
	var allFindings []analyzer.Finding
	ranNames := make([]string, 0, len(registry.All()))
	for _, a := range registry.All() {
		ranNames = append(ranNames, a.Name())
		findings, err := a.Analyze(ctx)
		if err != nil {
			continue
		}
		allFindings = append(allFindings, findings...)
	}

	stats := reporter.CodebaseStats{
		Packages:  result.Stats.PackageCount,
		Files:     result.Stats.FileCount,
		Functions: result.Stats.FunctionCount,
		Types:     result.Stats.TypeCount,
		Decls:     result.Stats.DeclCount,
	}

	rep := reporter.BuildReport(version, patterns, ranNames, stats, allFindings)

	return &Result{
		Findings:      allFindings,
		Context:       ctx,
		Stats:         stats,
		Report:        rep,
		LoaderResult:  result,
		AnalyzerNames: ranNames,
	}, nil
}

// RunSelectedAnalyzers loads the codebase and runs only the analyzers
// identified by name. Returns findings only (no report).
//gollaw:keep
func RunSelectedAnalyzers(dir string, names []string) ([]analyzer.Finding, *analyzer.Context, error) {
	result, err := loader.Load(loader.LoadConfig{
		Patterns: []string{"./..."},
		Dir:      dir,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("load codebase: %w", err)
	}

	ctx := &analyzer.Context{
		FSET:        result.FSET,
		Packages:    result.Packages,
		SSA:         result.SSA,
		SSAByPkg:    result.SSAByPkg,
		TypesByPkg:  result.TypesByPkg,
		SyntaxByPkg: result.SyntaxByPkg,
	}

	registry := analyzer.NewRegistry()
	selected := registry.Select(names)

	var allFindings []analyzer.Finding
	for _, a := range selected {
		findings, err := a.Analyze(ctx)
		if err != nil {
			continue
		}
		allFindings = append(allFindings, findings...)
	}

	return allFindings, ctx, nil
}

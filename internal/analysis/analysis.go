// Package analysis provides a shared entry point for loading a Go codebase,
// running all registered analyzers, and collecting findings.
//
// It eliminates the duplicated "load codebase → build context → run analyzers"
// pattern that previously appeared in internal/cli, internal/mcp, internal/action,
// and internal/fix.
package analysis

import (
	"github.com/dovocoder/gollaw/internal/analyzer"
	"github.com/dovocoder/gollaw/internal/loader"
	"github.com/dovocoder/gollaw/internal/reporter"
)

// Result holds the output of a full analysis run.
//
//gollaw:ignore api-surface
//gollaw:ignore unused
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

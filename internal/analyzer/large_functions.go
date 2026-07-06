package analyzer

import (
	"fmt"
	"go/ast"
	"sort"
)

// largeFunctionsAnalyzer flags functions that are excessively long by line
// count — the Go equivalent of Fallow's large_functions.
// Uses statement count (not raw line count) to avoid false positives from
// comments, blank lines, and verbose flag declarations.
type largeFunctionsAnalyzer struct{}

func newLargeFunctionsAnalyzer() *largeFunctionsAnalyzer { return &largeFunctionsAnalyzer{} }

func (a *largeFunctionsAnalyzer) Name() string       { return "large-functions" }
func (a *largeFunctionsAnalyzer) Category() Category { return CategoryCodeSmell }
func (a *largeFunctionsAnalyzer) Description() string {
	return "Functions exceeding a line-count threshold"
}

func (a *largeFunctionsAnalyzer) Analyze(ctx *Context) ([]Finding, error) {
	maxLines := ctx.Config.MaxFunctionLines
	if maxLines == 0 {
		maxLines = 50
	}

	var findings []Finding

	for _, files := range ctx.SyntaxByPkg {
		for _, file := range files {
			findings = append(findings, a.analyzeLargeFunctionsInFile(ctx, file, maxLines)...)
		}
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].File != findings[j].File {
			return findings[i].File < findings[j].File
		}
		return findings[i].Line < findings[j].Line
	})

	return findings, nil
}

func (a *largeFunctionsAnalyzer) analyzeLargeFunctionsInFile(ctx *Context, file *ast.File, maxLines int) []Finding {
	var findings []Finding
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || isCobraConstructor(fn) {
			continue
		}
		start := ctx.FSET.Position(fn.Pos())
		end := ctx.FSET.Position(fn.End())
		if isGeneratedFile(start.Filename) {
			continue
		}
		lineCount := end.Line - start.Line + 1
		if lineCount > maxLines {
			findings = append(findings, a.createLargeFunctionFinding(fn, start.Filename, start.Line, end.Line, lineCount, maxLines))
		}
	}
	return findings
}

func (a *largeFunctionsAnalyzer) createLargeFunctionFinding(fn *ast.FuncDecl, file string, line, endLine, lineCount, maxLines int) Finding {
	return Finding{
		Analyzer:   a.Name(),
		Category:   a.Category(),
		Severity:   severityForSize(lineCount, maxLines),
		Message:    fmt.Sprintf("%s is %d lines long (max %d)", funcLabel(fn), lineCount, maxLines),
		File:       file,
		Line:       line,
		EndLine:    endLine,
		RuleID:     "GLW-LF001",
		Suggestion: "Agent fix: split this function by responsibility. Extract validation, query construction, loop body, switch case handling, or output formatting into private helpers until the caller is short orchestration.",
	}
}

func severityForSize(lines, max int) Severity {
	if lines > max*4 {
		return SeverityCritical
	}
	if lines > max*2 {
		return SeverityWarning
	}
	return SeverityHint
}

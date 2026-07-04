package analyzer

import (
	"fmt"
	"go/ast"
	"sort"
)

// largeFunctionsAnalyzer flags functions that are excessively long by line
// count — the Go equivalent of Fallow's large_functions.
type largeFunctionsAnalyzer struct{}

func newLargeFunctionsAnalyzer() *largeFunctionsAnalyzer { return &largeFunctionsAnalyzer{} }

func (a *largeFunctionsAnalyzer) Name() string        { return "large-functions" }
func (a *largeFunctionsAnalyzer) Category() Category  { return CategoryCodeSmell }
func (a *largeFunctionsAnalyzer) Description() string { return "Functions exceeding a line-count threshold" }

func (a *largeFunctionsAnalyzer) Analyze(ctx *Context) ([]Finding, error) {
	maxLines := 50 // default threshold

	var findings []Finding

	for _, files := range ctx.SyntaxByPkg {
		for _, file := range files {
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				start := ctx.FSET.Position(fn.Pos())
				end := ctx.FSET.Position(fn.End())
				lineCount := end.Line - start.Line + 1

				if lineCount > maxLines {
					findings = append(findings, Finding{
						Analyzer:   a.Name(),
						Category:   a.Category(),
						Severity:   severityForSize(lineCount, maxLines),
						Message:     fmt.Sprintf("%s is %d lines long (max %d)", funcLabel(fn), lineCount, maxLines),
						File:        start.Filename,
						Line:        start.Line,
						EndLine:     end.Line,
						RuleID:      "GLW-LF001",
						Suggestion:  "Extract logic into smaller helper functions. Long functions are hard to test, review, and maintain.",
					})
				}
			}
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

func severityForSize(lines, max int) Severity {
	if lines > max*4 {
		return SeverityCritical
	}
	if lines > max*2 {
		return SeverityWarning
	}
	return SeverityInfo
}

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

func (a *largeFunctionsAnalyzer) Name() string        { return "large-functions" }
func (a *largeFunctionsAnalyzer) Category() Category  { return CategoryCodeSmell }
func (a *largeFunctionsAnalyzer) Description() string { return "Functions exceeding a line-count threshold" }

func (a *largeFunctionsAnalyzer) Analyze(ctx *Context) ([]Finding, error) {
	maxLines := 50 // default line threshold
	maxStmts := 25 // default statement threshold

	var findings []Finding

	for _, files := range ctx.SyntaxByPkg {
		for _, file := range files {
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				// Skip cobra command constructors — they're command
				// configurations (flag declarations, usage strings), not
				// logic functions. Their length is inherent to the number
				// of flags, not to code complexity.
				if isCobraConstructor(fn) {
					continue
				}
				start := ctx.FSET.Position(fn.Pos())
				end := ctx.FSET.Position(fn.End())
				// Skip generated files (sqlc, mockgen, etc.)
				if isGeneratedFile(start.Filename) {
					continue
				}
				lineCount := end.Line - start.Line + 1
				stmtCount := countStatements(fn.Body)

				// Flag if EITHER line count OR statement count exceeds threshold.
				// Statement count catches functions with real complexity even if
				// they're short in lines (dense code). Line count catches functions
				// with many comments/blank lines that are still hard to read.
				// We skip functions flagged ONLY by line count when the statement
				// count is very low (≤10) — that's almost certainly comments or
				// verbose struct literals, not real complexity.
				isLarge := lineCount > maxLines && stmtCount > 10 ||
					stmtCount > maxStmts
				if isLarge {
					findings = append(findings, Finding{
						Analyzer:   a.Name(),
						Category:   a.Category(),
						Severity:   severityForSize(lineCount, maxLines),
						Message:     fmt.Sprintf("%s is %d lines long (max %d)", funcLabel(fn), lineCount, maxLines),
						File:        start.Filename,
						Line:        start.Line,
						EndLine:    end.Line,
						RuleID:     "GLW-LF001",
						Suggestion: "Extract logic into smaller helper functions. Long functions are hard to test, review, and maintain.",
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

// countStatements counts the number of executable statements in a function body.
// This excludes comments, blank lines, and provides a better measure of
// function complexity than raw line count.
func countStatements(body *ast.BlockStmt) int {
	count := 0
	for _, stmt := range body.List {
		count += countStmt(stmt)
	}
	return count
}

func countStmt(stmt ast.Stmt) int {
	if stmt == nil {
		return 0
	}
	count := 1
	switch s := stmt.(type) {
	case *ast.BlockStmt:
		for _, sub := range s.List {
			count += countStmt(sub)
		}
		return count
	case *ast.IfStmt:
		count += countStmt(s.Body)
		if s.Else != nil {
			count += countStmt(s.Else)
		}
		return count
	case *ast.ForStmt:
		count += countStmt(s.Body)
		return count
	case *ast.RangeStmt:
		count += countStmt(s.Body)
		return count
	case *ast.SwitchStmt:
		for _, c := range s.Body.List {
			if cc, ok := c.(*ast.CaseClause); ok {
				for _, sub := range cc.Body {
					count += countStmt(sub)
				}
			}
		}
		return count
	case *ast.SelectStmt:
		for _, c := range s.Body.List {
			if cc, ok := c.(*ast.CommClause); ok {
				for _, sub := range cc.Body {
					count += countStmt(sub)
				}
			}
		}
		return count
	}
	return count
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

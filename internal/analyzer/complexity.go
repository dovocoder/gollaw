package analyzer

import (
	"fmt"
	"go/ast"
	"go/token"
	"sort"
)

// complexityAnalyzer computes cyclomatic and cognitive complexity for every
// function and flags hotspots.
type complexityAnalyzer struct{}

func newComplexityAnalyzer() *complexityAnalyzer { return &complexityAnalyzer{} }

func (a *complexityAnalyzer) Name() string        { return "complexity" }
func (a *complexityAnalyzer) Category() Category  { return CategoryComplexity }
func (a *complexityAnalyzer) Description() string { return "Cyclomatic and cognitive complexity hotspots" }

func (a *complexityAnalyzer) Analyze(ctx *Context) ([]Finding, error) {
	maxCyc, maxCog := a.getThresholds(ctx)
	var findings []Finding

	for _, files := range ctx.SyntaxByPkg {
		for _, file := range files {
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok {
					continue
				}
				findings = append(findings, a.checkFunctionComplexity(ctx, fn, maxCyc, maxCog)...)
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

// getThresholds returns the configured or default cyclomatic/cognitive
// complexity thresholds.
func (a *complexityAnalyzer) getThresholds(ctx *Context) (maxCyc, maxCog int) {
	maxCyc = ctx.Config.MaxCyclomatic
	if maxCyc == 0 {
		maxCyc = 15
	}
	maxCog = ctx.Config.MaxCognitive
	if maxCog == 0 {
		maxCog = 20
	}
	return maxCyc, maxCog
}

// checkFunctionComplexity checks a single function for cyclomatic or
// cognitive complexity violations.
func (a *complexityAnalyzer) checkFunctionComplexity(ctx *Context, fn *ast.FuncDecl, maxCyc, maxCog int) []Finding {
	cyc := cyclomaticComplexity(fn)
	cog := cognitiveComplexity(fn)

	if cyc > maxCyc {
		return []Finding{a.createCyclomaticFinding(ctx, fn, cyc, cog, maxCyc)}
	}
	if cog > maxCog {
		return []Finding{a.createCognitiveFinding(ctx, fn, cyc, cog, maxCog)}
	}
	return nil
}

// createCyclomaticFinding builds a Finding for high cyclomatic complexity.
func (a *complexityAnalyzer) createCyclomaticFinding(ctx *Context, fn *ast.FuncDecl, cyc, cog, maxCyc int) Finding {
	file, line, endLine := nodeInfo(ctx.FSET, fn)
	return Finding{
		Analyzer:   a.Name(),
		Category:   a.Category(),
		Severity:   severityForComplexity(cyc, maxCyc),
		Message:     fmt.Sprintf("%s has cyclomatic complexity %d (max %d)", funcLabel(fn), cyc, maxCyc),
		Detail:      fmt.Sprintf("cognitive complexity: %d", cog),
		File:        file,
		Line:        line,
		EndLine:     endLine,
		RuleID:      "GLW-CX001",
		Suggestion:  "Break this function into smaller helpers. High cyclomatic complexity makes testing and maintenance harder.",
	}
}

// createCognitiveFinding builds a Finding for high cognitive complexity.
func (a *complexityAnalyzer) createCognitiveFinding(ctx *Context, fn *ast.FuncDecl, cyc, cog, maxCog int) Finding {
	file, line, endLine := nodeInfo(ctx.FSET, fn)
	return Finding{
		Analyzer:   a.Name(),
		Category:   a.Category(),
		Severity:   severityForComplexity(cog, maxCog),
		Message:     fmt.Sprintf("%s has cognitive complexity %d (max %d)", funcLabel(fn), cog, maxCog),
		Detail:      fmt.Sprintf("cyclomatic complexity: %d", cyc),
		File:        file,
		Line:        line,
		EndLine:     endLine,
		RuleID:      "GLW-CX002",
		Suggestion:  "Simplify the nesting or extract sub-expressions. High cognitive complexity makes the function hard to read.",
	}
}

// cyclomaticComplexity counts decision points + 1.
func cyclomaticComplexity(fn *ast.FuncDecl) int {
	complexity := 1
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.IfStmt, *ast.ForStmt, *ast.RangeStmt, *ast.CaseClause, *ast.CommClause:
			complexity++
		case *ast.SwitchStmt:
			// Switch itself doesn't add; cases do (handled above).
		case *ast.BinaryExpr:
			if n.Op == token.LAND || n.Op == token.LOR {
				complexity++
			}
		}
		return true
	})
	return complexity
}

//gollaw:keep
// cognitiveComplexity approximates Cognitive Complexity (SonarSource style).
func cognitiveComplexity(fn *ast.FuncDecl) int {
	complexity := 0
	nesting := 0

	var walk func(n ast.Node)
	walk = func(n ast.Node) {
		ast.Inspect(n, func(node ast.Node) bool {
			if node == nil {
				return false
			}
			switch s := node.(type) {
			case *ast.IfStmt:
				complexity += 1 + nesting
				nesting++
				walk(s.Body)
				if s.Else != nil {
					if _, ok := s.Else.(*ast.BlockStmt); ok {
						complexity += 1 + nesting
					}
					walk(s.Else)
				}
				nesting--
				return false
			case *ast.ForStmt, *ast.RangeStmt:
				complexity += 1 + nesting
				nesting++
				ast.Inspect(s, func(inner ast.Node) bool {
					if inner == s {
						return true
					}
					walk(inner)
					return false
				})
				nesting--
				return false
			case *ast.SwitchStmt:
				complexity += 1 + nesting
				nesting++
				for _, stmt := range s.Body.List {
					if clause, ok := stmt.(*ast.CaseClause); ok {
						complexity += len(clause.List)
					}
					for _, c := range stmt.(*ast.CaseClause).Body {
						walk(c)
					}
				}
				nesting--
				return false
			case *ast.BinaryExpr:
				if s.Op == token.LAND || s.Op == token.LOR {
					complexity++
				}
			}
			return true
		})
	}

	if fn.Body != nil {
		walk(fn.Body)
	}
	return complexity
}

func severityForComplexity(val, max int) Severity {
	ratio := float64(val) / float64(max)
	if ratio >= 3.0 {
		return SeverityCritical
	}
	if ratio >= 2.0 {
		return SeverityWarning
	}
	return SeverityInfo
}

func funcLabel(fn *ast.FuncDecl) string {
	if fn.Recv != nil && len(fn.Recv.List) > 0 {
		recvType := "unknown"
		if ident, ok := fn.Recv.List[0].Type.(*ast.Ident); ok {
			recvType = ident.Name
		} else if star, ok := fn.Recv.List[0].Type.(*ast.StarExpr); ok {
			if ident, ok := star.X.(*ast.Ident); ok {
				recvType = ident.Name
			}
		}
		return fmt.Sprintf("(%s).%s", recvType, fn.Name.Name)
	}
	return fn.Name.Name
}

package analyzer

import (
	"fmt"
	"go/ast"
	"regexp"
	"sort"
	"strings"
)

// securityAnalyzer detects potential security issues: hardcoded secrets,
// TODO/FIXME comments, unsafe usage, and SQL injection patterns — inspired
// by Fallow's security analysis module.
type securityAnalyzer struct{}

func newSecurityAnalyzer() *securityAnalyzer { return &securityAnalyzer{} }

func (a *securityAnalyzer) Name() string        { return "security" }
func (a *securityAnalyzer) Category() Category  { return CategoryCodeSmell }
func (a *securityAnalyzer) Description() string { return "Hardcoded secrets, TODO/FIXME comments, unsafe usage, SQL injection patterns" }

func (a *securityAnalyzer) Analyze(ctx *Context) ([]Finding, error) {
	var findings []Finding

	// Patterns for hardcoded secrets.
	secretPatterns := []struct {
		name   string
		regex  *regexp.Regexp
		ruleID string
	}{
		{"hardcoded API key", regexp.MustCompile(`(?i)(api[_-]?key|apikey)\s*[:=]\s*["'][a-zA-Z0-9]{20,}["']`), "GLW-SC001"},
		{"hardcoded password", regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[:=]\s*["'][^"']{4,}["']`), "GLW-SC002"},
		{"hardcoded token", regexp.MustCompile(`(?i)(token|secret|bearer)\s*[:=]\s*["'][a-zA-Z0-9._\-]{20,}["']`), "GLW-SC003"},
		{"AWS access key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`), "GLW-SC004"},
		{"private key", regexp.MustCompile(`-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----`), "GLW-SC005"},
	}

	// TODO/FIXME patterns.
	todoPattern := regexp.MustCompile(`(?i)\b(TODO|FIXME|HACK|XXX|BUG)\b[:\s]`)

	for _, files := range ctx.SyntaxByPkg {
		for _, file := range files {
			// Scan comments for TODOs/FIXMEs.
			ast.Inspect(file, func(n ast.Node) bool {
				switch node := n.(type) {
				case *ast.Comment:
					text := node.Text
					pos := ctx.FSET.Position(node.Pos())
					if todoPattern.MatchString(text) {
						findings = append(findings, Finding{
							Analyzer:  a.Name(),
							Category:  a.Category(),
							Severity:  SeverityInfo,
							Message:    fmt.Sprintf("found %s", strings.TrimSpace(text)),
							File:       pos.Filename,
							Line:       pos.Line,
							RuleID:     "GLW-SC010",
							Suggestion: "Resolve this technical debt item. TODOs and FIXMEs accumulate over time.",
						})
					}
					// Check for secrets in comments.
					for _, sp := range secretPatterns {
						if sp.regex.MatchString(text) {
							findings = append(findings, Finding{
								Analyzer:  a.Name(),
								Category:  a.Category(),
								Severity:  SeverityCritical,
								Message:    fmt.Sprintf("potential %s in comment", sp.name),
								File:       pos.Filename,
								Line:       pos.Line,
								RuleID:     sp.ruleID,
								Suggestion: "Never put secrets in source code or comments. Use environment variables or a secret manager.",
							})
						}
					}
				}
				return true
			})

			// Scan string literals for secrets and unsafe patterns.
			ast.Inspect(file, func(n ast.Node) bool {
				switch node := n.(type) {
				case *ast.BasicLit:
					if node.Kind == 9 { // STRING
						val := node.Value
						pos := ctx.FSET.Position(node.Pos())
						for _, sp := range secretPatterns {
							if sp.regex.MatchString(val) {
								findings = append(findings, Finding{
									Analyzer:  a.Name(),
									Category:  a.Category(),
									Severity:  SeverityCritical,
									Message:    fmt.Sprintf("potential %s in string literal", sp.name),
									File:       pos.Filename,
									Line:       pos.Line,
									RuleID:     sp.ruleID,
									Suggestion: "Never hardcode secrets. Use environment variables or a secret manager.",
								})
							}
						}
					}
				}
				return true
			})

			// Detect unsafe usage.
			ast.Inspect(file, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				ident, ok := sel.X.(*ast.Ident)
				if !ok {
					return true
				}
				pos := ctx.FSET.Position(sel.Pos())

				// unsafe.Pointer, unsafe.Sizeof, etc.
				if ident.Name == "unsafe" {
					findings = append(findings, Finding{
						Analyzer:  a.Name(),
						Category:  a.Category(),
						Severity:  SeverityWarning,
						Message:    fmt.Sprintf("unsafe.%s usage", sel.Sel.Name),
						File:       pos.Filename,
						Line:       pos.Line,
						RuleID:     "GLW-SC020",
						Suggestion: "unsafe operations bypass Go's type and memory safety. Use only when absolutely necessary and well-documented.",
					})
				}

				// SQL string concatenation pattern.
				if ident.Name == "fmt" && (sel.Sel.Name == "Sprintf" || sel.Sel.Name == "Format") {
					// Check if the format string contains SQL keywords.
					// This is a heuristic — check the parent call.
					return true
				}

				return true
			})

			// Detect SQL string concatenation (fmt.Sprintf with SQL).
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				ident, ok := sel.X.(*ast.Ident)
				if !ok || ident.Name != "fmt" {
					return true
				}
				if sel.Sel.Name != "Sprintf" {
					return true
				}
				if len(call.Args) == 0 {
					return true
				}
				// Check if first arg is a string containing SQL keywords.
				if lit, ok := call.Args[0].(*ast.BasicLit); ok && lit.Kind == 9 {
					val := strings.ToLower(lit.Value)
					if containsAny(val, "select ", "insert ", "update ", "delete ", "drop ", "create table", "where ") {
						pos := ctx.FSET.Position(call.Pos())
						findings = append(findings, Finding{
							Analyzer:  a.Name(),
							Category:  a.Category(),
							Severity:  SeverityCritical,
							Message:    "SQL query built via fmt.Sprintf — potential SQL injection",
							File:       pos.Filename,
							Line:       pos.Line,
							RuleID:     "GLW-SC030",
							Suggestion: "Use parameterized queries (db.Query(sql, args...)) instead of string formatting.",
						})
					}
				}
				return true
			})
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

func containsAny(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

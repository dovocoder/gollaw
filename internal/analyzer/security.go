package analyzer

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"regexp"
	"sort"
	"strings"
)

// securityAnalyzer detects potential security issues: hardcoded secrets,
// todo/fixme comments, unsafe usage, and SQL injection patterns — inspired
// by Fallow's security analysis module.
type securityAnalyzer struct{}

func newSecurityAnalyzer() *securityAnalyzer { return &securityAnalyzer{} }

func (a *securityAnalyzer) Name() string       { return "security" }
func (a *securityAnalyzer) Category() Category { return CategoryCodeSmell }
func (a *securityAnalyzer) Description() string {
	return "Hardcoded secrets, TODO/FIXME comments, unsafe usage, SQL injection patterns"
}

type secretPattern struct {
	name   string
	regex  *regexp.Regexp
	ruleID string
}

func (a *securityAnalyzer) Analyze(ctx *Context) ([]Finding, error) {
	var findings []Finding

	secretPatterns := []secretPattern{
		{"hardcoded API key", regexp.MustCompile(`(?i)(api[_-]?key|apikey)\s*[:=]\s*["'][a-zA-Z0-9]{20,}["']`), "GLW-SC001"},
		{"hardcoded password", regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[:=]\s*["'][^"']{4,}["']`), "GLW-SC002"},
		{"hardcoded token", regexp.MustCompile(`(?i)(token|secret|bearer)\s*[:=]\s*["'][a-zA-Z0-9._\-]{20,}["']`), "GLW-SC003"},
		{"AWS access key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`), "GLW-SC004"},
		{"private key", regexp.MustCompile(`-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----`), "GLW-SC005"},
	}
	todoPattern := regexp.MustCompile(`\b(TODO|FIXME|HACK|XXX|BUG)\b[:\s]`)

	typeInfoByFile := typeInfoBySyntaxFile(ctx)
	for _, files := range ctx.SyntaxByPkg {
		for _, file := range files {
			findings = append(findings, a.checkTODOComments(ctx, file, todoPattern)...)
			findings = append(findings, a.checkHardcodedSecrets(ctx, file, secretPatterns)...)
			findings = append(findings, a.checkUnsafeUsage(ctx, file)...)
			findings = append(findings, a.checkSQLInjection(ctx, file, typeInfoByFile[file])...)
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

// checkTODOComments scans comments for pending markers and secrets in comments.
func (a *securityAnalyzer) checkTODOComments(ctx *Context, file *ast.File, todoPattern *regexp.Regexp) []Finding {
	var findings []Finding
	ast.Inspect(file, func(n ast.Node) bool {
		node, ok := n.(*ast.Comment)
		if !ok {
			return true
		}
		text := node.Text
		pos := ctx.FSET.Position(node.Pos())
		if todoPattern.MatchString(text) {
			findings = append(findings, Finding{
				Analyzer:   a.Name(),
				Category:   a.Category(),
				Severity:   SeverityInfo,
				Message:    fmt.Sprintf("found %s", strings.TrimSpace(text)),
				File:       pos.Filename,
				Line:       pos.Line,
				RuleID:     "GLW-SC010",
				Suggestion: "Resolve this technical debt item. TODOs and FIXMEs accumulate over time.",
			})
		}
		return true
	})
	return findings
}

// checkHardcodedSecrets scans comments and string literals for hardcoded secrets.
func (a *securityAnalyzer) checkHardcodedSecrets(ctx *Context, file *ast.File, patterns []secretPattern) []Finding {
	var findings []Finding
	findings = append(findings, a.scanCommentsForSecrets(ctx, file, patterns)...)
	findings = append(findings, a.scanStringLiteralsForSecrets(ctx, file, patterns)...)
	return findings
}

// scanCommentsForSecrets inspects comment nodes for secret patterns.
func (a *securityAnalyzer) scanCommentsForSecrets(ctx *Context, file *ast.File, patterns []secretPattern) []Finding {
	var findings []Finding
	ast.Inspect(file, func(n ast.Node) bool {
		node, ok := n.(*ast.Comment)
		if !ok {
			return true
		}
		text := node.Text
		pos := ctx.FSET.Position(node.Pos())
		for _, sp := range patterns {
			if sp.regex.MatchString(text) {
				findings = append(findings, Finding{
					Analyzer:   a.Name(),
					Category:   a.Category(),
					Severity:   SeverityCritical,
					Message:    fmt.Sprintf("potential %s in comment", sp.name),
					File:       pos.Filename,
					Line:       pos.Line,
					RuleID:     sp.ruleID,
					Suggestion: "Never put secrets in source code or comments. Use environment variables or a secret manager.",
				})
			}
		}
		return true
	})
	return findings
}

// scanStringLiteralsForSecrets inspects string literals for secret patterns.
func (a *securityAnalyzer) scanStringLiteralsForSecrets(ctx *Context, file *ast.File, patterns []secretPattern) []Finding {
	var findings []Finding
	ast.Inspect(file, func(n ast.Node) bool {
		node, ok := n.(*ast.BasicLit)
		if !ok || node.Kind != token.STRING {
			return true
		}
		val := node.Value
		pos := ctx.FSET.Position(node.Pos())
		for _, sp := range patterns {
			if sp.regex.MatchString(val) {
				findings = append(findings, Finding{
					Analyzer:   a.Name(),
					Category:   a.Category(),
					Severity:   SeverityCritical,
					Message:    fmt.Sprintf("potential %s in string literal", sp.name),
					File:       pos.Filename,
					Line:       pos.Line,
					RuleID:     sp.ruleID,
					Suggestion: "Never hardcode secrets. Use environment variables or a secret manager.",
				})
			}
		}
		return true
	})
	return findings
}

// checkUnsafeUsage detects unsafe.* usage.
func (a *securityAnalyzer) checkUnsafeUsage(ctx *Context, file *ast.File) []Finding {
	var findings []Finding
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
				Analyzer:   a.Name(),
				Category:   a.Category(),
				Severity:   SeverityWarning,
				Message:    fmt.Sprintf("unsafe.%s usage", sel.Sel.Name),
				File:       pos.Filename,
				Line:       pos.Line,
				RuleID:     "GLW-SC020",
				Suggestion: "unsafe operations bypass Go's type and memory safety. Use only when absolutely necessary and well-documented.",
			})
		}
		return true
	})
	return findings
}

// checkSQLInjection detects SQL query strings that mix SQL syntax with dynamic
// data at database execution sites. Constant SQL assembly is allowed; dynamic
// values must be passed as bind parameters instead of interpolated into SQL.
func (a *securityAnalyzer) checkSQLInjection(ctx *Context, file *ast.File, info *types.Info) []Finding {
	var findings []Finding
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		argIndex, ok := sqlStringArgIndex(sel.Sel.Name)
		if !ok || len(call.Args) <= argIndex {
			return true
		}
		arg := call.Args[argIndex]
		if !isPotentialSQLExpr(info, arg) || !isDynamicSQLExpr(info, arg) {
			return true
		}
		pos := ctx.FSET.Position(arg.Pos())
		findings = append(findings, Finding{
			Analyzer:   a.Name(),
			Category:   a.Category(),
			Severity:   SeverityCritical,
			Message:    "SQL query mixes SQL text with dynamic values",
			File:       pos.Filename,
			Line:       pos.Line,
			RuleID:     "GLW-SC030",
			Suggestion: "Agent fix: move dynamic values into bind parameters. If the dynamic part is a table or column name, replace free-form input with a strict allow-list function that returns fixed quoted SQL fragments.",
		})
		return true
	})
	return findings
}

func typeInfoBySyntaxFile(ctx *Context) map[*ast.File]*types.Info {
	out := make(map[*ast.File]*types.Info)
	for _, pkg := range ctx.Packages {
		if pkg.TypesInfo == nil {
			continue
		}
		for _, file := range pkg.Syntax {
			out[file] = pkg.TypesInfo
		}
	}
	return out
}

func sqlStringArgIndex(method string) (int, bool) {
	switch method {
	case "Exec", "Query", "QueryRow", "Prepare":
		return 0, true
	case "ExecContext", "QueryContext", "QueryRowContext", "PrepareContext":
		return 1, true
	default:
		return 0, false
	}
}

func isDynamicSQLExpr(info *types.Info, expr ast.Expr) bool {
	if isConstStringExpr(info, expr) {
		return false
	}
	switch e := expr.(type) {
	case *ast.CallExpr:
		if isFmtSprintfCall(e) {
			return true
		}
	case *ast.BinaryExpr:
		if e.Op == token.ADD && (isPotentialSQLExpr(info, e.X) || isPotentialSQLExpr(info, e.Y)) {
			return true
		}
	}
	return false
}

func isPotentialSQLExpr(info *types.Info, expr ast.Expr) bool {
	if s, ok := constStringValue(info, expr); ok {
		return looksLikeSQL(s)
	}
	switch e := expr.(type) {
	case *ast.BasicLit:
		if e.Kind != token.STRING {
			return false
		}
		return looksLikeSQL(e.Value)
	case *ast.BinaryExpr:
		return e.Op == token.ADD && (isPotentialSQLExpr(info, e.X) || isPotentialSQLExpr(info, e.Y))
	case *ast.CallExpr:
		return isFmtSprintfCall(e) && len(e.Args) > 0 && isPotentialSQLExpr(info, e.Args[0])
	default:
		return false
	}
}

func isConstStringExpr(info *types.Info, expr ast.Expr) bool {
	_, ok := constStringValue(info, expr)
	return ok
}

func constStringValue(info *types.Info, expr ast.Expr) (string, bool) {
	if info == nil {
		return "", false
	}
	tv, ok := info.Types[expr]
	if !ok || tv.Value == nil || tv.Value.Kind() != constant.String {
		return "", false
	}
	return constant.StringVal(tv.Value), true
}

func isFmtSprintfCall(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Sprintf" {
		return false
	}
	ident, ok := sel.X.(*ast.Ident)
	return ok && ident.Name == "fmt"
}

func looksLikeSQL(s string) bool {
	lower := strings.ToLower(s)
	keywords := []string{
		"select ", "insert ", "update ", "delete ", "drop ", "alter ",
		"create ", "replace ", "pragma ", " where ", " from ", " into ",
	}
	for _, keyword := range keywords {
		if strings.Contains(lower, keyword) {
			return true
		}
	}
	return false
}

package analyzer

import (
	"fmt"
	"go/ast"
	"go/token"
	"sort"
	"strings"
	"unicode"
)

// namingAnalyzer checks Go naming conventions — inspired by Fallow's
// convention checks. Flags exported names that use snake_case or
// inconsistent casing, and unexported names that look like they should
// be exported (e.g. all-caps acronyms).
type namingAnalyzer struct{}

func newNamingAnalyzer() *namingAnalyzer { return &namingAnalyzer{} }

func (a *namingAnalyzer) Name() string        { return "naming" }
func (a *namingAnalyzer) Category() Category  { return CategoryCodeSmell }
func (a *namingAnalyzer) Description() string { return "Go naming convention violations" }

func (a *namingAnalyzer) Analyze(ctx *Context) ([]Finding, error) {
	var findings []Finding

	for _, files := range ctx.SyntaxByPkg {
		for _, file := range files {
			findings = append(findings, a.checkFunctionNames(ctx, file)...)
			findings = append(findings, a.checkTypeNames(ctx, file)...)
			findings = append(findings, a.checkVariableNames(ctx, file)...)
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

// checkFunctionNames checks function declarations for naming convention violations.
func (a *namingAnalyzer) checkFunctionNames(ctx *Context, file *ast.File) []Finding {
	var findings []Finding
	for _, decl := range file.Decls {
		d, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		name := d.Name.Name
		pos := ctx.FSET.Position(d.Name.Pos())
		findings = append(findings, checkName("function", name, pos, d.Name.IsExported())...)
	}
	return findings
}

// checkTypeNames checks type declarations for naming convention violations.
func (a *namingAnalyzer) checkTypeNames(ctx *Context, file *ast.File) []Finding {
	var findings []Finding
	for _, decl := range file.Decls {
		d, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range d.Specs {
			if s, ok := spec.(*ast.TypeSpec); ok {
				pos := ctx.FSET.Position(s.Name.Pos())
				findings = append(findings, checkName("type", s.Name.Name, pos, s.Name.IsExported())...)
			}
		}
	}
	return findings
}

// checkVariableNames checks variable and constant declarations, and import
// aliases, for naming convention violations.
func (a *namingAnalyzer) checkVariableNames(ctx *Context, file *ast.File) []Finding {
	var findings []Finding

	// Check variable and constant names.
	for _, decl := range file.Decls {
		d, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range d.Specs {
			s, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for _, name := range s.Names {
				pos := ctx.FSET.Position(name.Pos())
				kind := "variable"
				if d.Tok.String() == "const" {
					kind = "constant"
				}
				findings = append(findings, checkName(kind, name.Name, pos, name.IsExported())...)
			}
		}
	}

	// Check import aliases for unnecessary aliases.
	for _, imp := range file.Imports {
		if imp.Name == nil {
			continue
		}
		alias := imp.Name.Name
		path := strings.Trim(imp.Path.Value, `"`)
		pkgName := lastSegment(path)
		if alias == pkgName {
			pos := ctx.FSET.Position(imp.Pos())
			findings = append(findings, Finding{
				Analyzer:   a.Name(),
				Category:   a.Category(),
				Severity:   SeverityHint,
				Message:     fmt.Sprintf("import alias %q is the same as the package name — remove it", alias),
				File:        pos.Filename,
				Line:        pos.Line,
				RuleID:      "GLW-NM003",
				Suggestion:  "Remove the alias: import \"" + path + "\" instead of import " + alias + " \"" + path + "\".",
			})
		}
	}

	return findings
}

// nonStandardInitialisms lists common initialisms that should be uppercase.
var nonStandardInitialisms = []string{"Url", "Id", "Http", "Https", "Sql", "Json", "Xml", "Html", "Ssl", "Tcp", "Udp", "Ip", "Api"}

func checkName(kind, name string, pos token.Position, exported bool) []Finding {
	var findings []Finding
	findings = append(findings, checkSnakeCase(kind, name, pos)...)
	if exported {
		findings = append(findings, checkAllCaps(kind, name, pos)...)
		findings = append(findings, checkInitialisms(kind, name, pos)...)
	}
	return findings
}

// checkSnakeCase flags names containing underscores (excluding _test/_mock).
func checkSnakeCase(kind, name string, pos token.Position) []Finding {
	if !strings.Contains(name, "_") || strings.HasPrefix(name, "_") {
		return nil
	}
	// Allow _test suffix for test doubles.
	if strings.HasSuffix(name, "_test") || strings.HasSuffix(name, "_mock") {
		return nil
	}
	return []Finding{{
		Analyzer:   "naming",
		Category:   CategoryCodeSmell,
		Severity:   SeverityHint,
		Message:     fmt.Sprintf("%s %q uses snake_case — Go convention is camelCase/PascalCase", kind, name),
		File:        pos.Filename,
		Line:        pos.Line,
		RuleID:      "GLW-NM001",
		Suggestion:  fmt.Sprintf("Rename to %s (remove underscores, capitalize each word).", toCamelCase(name)),
	}}
}

// checkAllCaps flags exported ALL_CAPS names.
func checkAllCaps(kind, name string, pos token.Position) []Finding {
	if !isAllCaps(name) {
		return nil
	}
	return []Finding{{
		Analyzer:   "naming",
		Category:   CategoryCodeSmell,
		Severity:   SeverityHint,
		Message:     fmt.Sprintf("%s %q is ALL_CAPS — Go convention is PascalCase for exported names", kind, name),
		File:        pos.Filename,
		Line:        pos.Line,
		RuleID:      "GLW-NM002",
		Suggestion:  fmt.Sprintf("Rename to %s (PascalCase, not ALL_CAPS).", toPascalCase(name)),
	}}
}

// checkInitialisms flags non-standard initialism casing (Url → URL, Id → ID, etc.).
func checkInitialisms(kind, name string, pos token.Position) []Finding {
	var findings []Finding
	for _, bad := range nonStandardInitialisms {
		if !strings.Contains(name, bad) {
			continue
		}
		fixed := strings.ReplaceAll(name, bad, strings.ToUpper(bad))
		findings = append(findings, Finding{
			Analyzer:   "naming",
			Category:   CategoryCodeSmell,
			Severity:   SeverityHint,
			Message:     fmt.Sprintf("%s %q contains non-standard initialism %q — Go convention is uppercase (e.g. %s)", kind, name, bad, fixed),
			File:        pos.Filename,
			Line:        pos.Line,
			RuleID:      "GLW-NM004",
			Suggestion:  fmt.Sprintf("Rename to %s (use uppercase initialism).", fixed),
		})
	}
	return findings
}

// goInitialisms are standard Go initialisms that are always uppercase.
// From https://github.com/golang/lint/blob/master/lint.go#L702
var goInitialisms = map[string]bool{
	"ACL":   true, "API":   true, "ASCII": true, "CPU":   true, "CSS":   true,
	"DNS":   true, "EOF":   true, "GUID":  true, "HTML":  true, "HTTP":  true,
	"HTTPS": true, "ID":    true, "IP":    true, "JSON":  true, "LHS":   true,
	"QPS":   true, "RAM":   true, "RHS":   true, "RPC":   true, "SLA":   true,
	"SMTP":  true, "SQL":   true, "SSH":   true, "TCP":   true, "TLS":   true,
	"TTL":   true, "UDP":   true, "UI":    true, "UID":   true, "UUID":  true,
	"URI":   true, "URL":   true, "UTF8":  true, "VM":    true, "XML":   true,
	"XMPP":  true, "XSRF":  true, "XSS":   true, "DB":    true, "DBTX":  true,
	"WA":    true, "FTS":   true, "FTS5":  true, "JID":   true, "CGO":   true,
	"OS":    true, "IO":    true, "GPU":   true, "I18N":  true, "L10N":  true,
}

func isAllCaps(s string) bool {
	// Skip known Go initialisms (DB, API, URL, etc.)
	if goInitialisms[s] {
		return false
	}
	for _, r := range s {
		if r == '_' {
			continue
		}
		if !unicode.IsUpper(r) && !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

func toCamelCase(s string) string {
	parts := strings.Split(s, "_")
	result := parts[0]
	for _, p := range parts[1:] {
		if len(p) > 0 {
			result += strings.ToUpper(p[:1]) + p[1:]
		}
	}
	return result
}

func toPascalCase(s string) string {
	cc := toCamelCase(s)
	if len(cc) > 0 {
		return strings.ToUpper(cc[:1]) + cc[1:]
	}
	return cc
}

func lastSegment(s string) string {
	parts := strings.Split(s, "/")
	return parts[len(parts)-1]
}

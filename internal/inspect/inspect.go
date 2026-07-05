// Package inspect provides interactive file/symbol inspection capabilities.
package inspect

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"os"
	"path/filepath"
	"strings"

	"github.com/dovocoder/gollaw/internal/analyzer"
	"github.com/dovocoder/gollaw/internal/codeowners"
	"github.com/dovocoder/gollaw/internal/trace"
)

// inspectTarget represents the target of inspection: either a file path or
// a symbol name.
type inspectTarget struct {
	Value  string
	IsFile bool
}

// fileIdentity holds basic identity information about a file.
type fileIdentity struct {
	Path      string `json:"path"`
	Package   string `json:"package"`
	LineCount int    `json:"lineCount"`
	FuncCount int    `json:"funcCount"`
}

// inspectResult holds the result of inspecting a file or symbol.
type inspectResult struct {
	Target        string             `json:"target"`
	Kind          string             `json:"kind"` // "file" or "symbol"
	fileIdentity  fileIdentity       `json:"-"`
	Findings      []analyzer.Finding `json:"findings"`
	HealthScore   int                `json:"healthScore"`
	Grade         string             `json:"grade"`
	CallChain     []string           `json:"callChain,omitempty"`
	DirectCallers []string           `json:"directCallers,omitempty"`
	DirectCallees []string           `json:"directCallees,omitempty"`
	Coverage      bool               `json:"coverage"`
	Owners        []string           `json:"owners,omitempty"`
}

// Inspect analyses a target (file path or symbol name) and returns a detailed
// inspection result. The ctx parameter provides the loaded codebase context.
// If target looks like a file path (contains "/" or ends with ".go"), it is
// treated as a file; otherwise as a symbol name.
func Inspect(ctx *analyzer.Context, target string, dir string) (*inspectResult, error) {
	isFile := strings.Contains(target, "/") || strings.HasSuffix(target, ".go")
	if isFile {
		return inspectFile(ctx, target, dir)
	}
	return inspectSymbol(ctx, target, dir)
}

// inspectFile analyses a single file.
func inspectFile(ctx *analyzer.Context, filePath string, dir string) (*inspectResult, error) {
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		absPath = filePath
	}

	identity := findFileIdentity(ctx, filePath, absPath)
	fileFindings := collectFileFindings(ctx, filePath, absPath)
	healthScore, grade := computeFileHealth(fileFindings)
	coverage := hasTestFile(absPath)
	owners := lookupOwners(filePath, dir)

	return &inspectResult{
		Target:       filePath,
		Kind:         "file",
		fileIdentity: identity,
		Findings:     fileFindings,
		HealthScore:  healthScore,
		Grade:        grade,
		Coverage:     coverage,
		Owners:       owners,
	}, nil
}

// findFileIdentity locates the file in loaded packages and gathers identity info.
func findFileIdentity(ctx *analyzer.Context, filePath, absPath string) fileIdentity {
	identity := fileIdentity{Path: filePath}
	for pPath, files := range ctx.SyntaxByPkg {
		if found, ok := findFileInPkg(ctx, files, pPath, filePath, absPath); ok {
			identity = found
			identity.Path = filePath
			break
		}
	}
	return identity
}

// findFileInPkg searches for a file in a single package's file list.
func findFileInPkg(ctx *analyzer.Context, files []*ast.File, pPath, filePath, absPath string) (fileIdentity, bool) {
	for _, file := range files {
		pos := ctx.FSET.Position(file.Pos())
		if pos.Filename == absPath || pos.Filename == filePath {
			identity := fileIdentity{Package: pPath}
			if fileEnd := ctx.FSET.Position(file.End()); fileEnd.Line > 0 {
				identity.LineCount = fileEnd.Line
			}
			identity.FuncCount = countFuncDecls(file)
			return identity, true
		}
	}
	return fileIdentity{}, false
}

// countFuncDecls counts function declarations in a file.
func countFuncDecls(file *ast.File) int {
	var count int
	for _, decl := range file.Decls {
		if _, ok := decl.(*ast.FuncDecl); ok {
			count++
		}
	}
	return count
}

// collectFileFindings runs all analyzers and filters findings to the target file.
func collectFileFindings(ctx *analyzer.Context, filePath, absPath string) []analyzer.Finding {
	allFindings := runAllAnalyzers(ctx)
	var fileFindings []analyzer.Finding
	for _, f := range allFindings {
		if f.File == filePath || f.File == absPath || strings.HasSuffix(f.File, filePath) {
			fileFindings = append(fileFindings, f)
		}
	}
	return fileFindings
}

// runAllAnalyzers executes every registered analyzer and collects findings.
func runAllAnalyzers(ctx *analyzer.Context) []analyzer.Finding {
	var allFindings []analyzer.Finding
	registry := analyzer.NewRegistry()
	for _, a := range registry.All() {
		findings, err := a.Analyze(ctx)
		if err != nil {
			continue
		}
		allFindings = append(allFindings, findings...)
	}
	return allFindings
}

// inspectSymbol analyses a symbol (function/method) by name.
func inspectSymbol(ctx *analyzer.Context, symbol string, dir string) (*inspectResult, error) {
	directCallers := traceDirectCallers(ctx, symbol)
	directCallees, callChain := traceDirectCallees(ctx, symbol)
	symbolFindings := collectSymbolFindings(ctx, symbol)
	healthScore, grade := computeFileHealth(symbolFindings)

	return &inspectResult{
		Target:        symbol,
		Kind:          "symbol",
		Findings:      symbolFindings,
		HealthScore:   healthScore,
		Grade:         grade,
		CallChain:     callChain,
		DirectCallers: directCallers,
		DirectCallees: directCallees,
	}, nil
}

// traceDirectCallers finds immediate callers of a symbol.
func traceDirectCallers(ctx *analyzer.Context, symbol string) []string {
	result, err := trace.TraceCallers(ctx, symbol, 1)
	if err != nil || result == nil {
		return nil
	}
	var callers []string
	for _, chain := range result.Chains {
		if len(chain) > 1 {
			callers = append(callers, chain[0].Function)
		}
	}
	return callers
}

// traceDirectCallees finds immediate callees and builds the call chain.
func traceDirectCallees(ctx *analyzer.Context, symbol string) ([]string, []string) {
	result, err := trace.TraceCallees(ctx, symbol, 1)
	if err != nil || result == nil {
		return nil, nil
	}
	var callees []string
	var callChain []string
	for _, chain := range result.Chains {
		if len(chain) > 1 {
			callees = append(callees, chain[1].Function)
		}
		for _, node := range chain {
			callChain = append(callChain, node.Function)
		}
	}
	return callees, callChain
}

// collectSymbolFindings runs all analyzers and filters findings mentioning the symbol.
func collectSymbolFindings(ctx *analyzer.Context, symbol string) []analyzer.Finding {
	allFindings := runAllAnalyzers(ctx)
	var symbolFindings []analyzer.Finding
	for _, f := range allFindings {
		if strings.Contains(f.Message, symbol) || strings.Contains(f.Detail, symbol) {
			symbolFindings = append(symbolFindings, f)
		}
	}
	return symbolFindings
}

// computeFileHealth computes a simple health score and grade from findings.
func computeFileHealth(findings []analyzer.Finding) (int, string) {
	weights := map[analyzer.Severity]int{
		analyzer.SeverityCritical: 25,
		analyzer.SeverityWarning:  8,
		analyzer.SeverityInfo:     2,
		analyzer.SeverityHint:     1,
	}

	penalty := 0
	for _, f := range findings {
		penalty += weights[f.Severity]
	}

	score := 100 - penalty
	if score < 0 {
		score = 0
	}
	return score, healthGrade(score)
}

// healthGrade converts a numeric score to a letter grade.
func healthGrade(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 60:
		return "D"
	case score >= 50:
		return "E"
	default:
		return "F"
	}
}

// hasTestFile checks if a _test.go file exists alongside the given file.
func hasTestFile(filePath string) bool {
	dir := filepath.Dir(filePath)
	base := filepath.Base(filePath)
	testBase := strings.TrimSuffix(base, ".go") + "_test.go"
	testPath := filepath.Join(dir, testBase)
	_, err := os.Stat(testPath)
	return err == nil
}

// lookupOwners tries to find CODEOWNERS for the given file path.
func lookupOwners(filePath string, dir string) []string {
	ownersFile, err := codeowners.FindCodeOwnersFile(dir)
	if err != nil {
		return nil
	}
	owners, err := codeowners.Parse(ownersFile)
	if err != nil {
		return nil
	}
	return codeowners.FindOwners(filePath, owners)
}

// FormatInspectText renders an inspect result as human-readable text.
func FormatInspectText(result *inspectResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Inspection: %s (%s)\n", result.Target, result.Kind)
	fmt.Fprintf(&b, "%s\n", strings.Repeat("─", 50))
	if result.Kind == "file" {
		formatFileSection(&b, result)
	} else {
		formatSymbolSection(&b, result)
	}
	formatFindingsSection(&b, result)
	return b.String()
}

// formatFileSection writes the file-specific portion of the text report.
func formatFileSection(b *strings.Builder, result *inspectResult) {
	fmt.Fprintf(b, "File: %s\n", result.fileIdentity.Path)
	fmt.Fprintf(b, "Package: %s\n", result.fileIdentity.Package)
	fmt.Fprintf(b, "Lines: %d  |  Functions: %d\n", result.fileIdentity.LineCount, result.fileIdentity.FuncCount)
	fmt.Fprintf(b, "Health: %d/100 (grade: %s)\n", result.HealthScore, result.Grade)
	fmt.Fprintf(b, "Has tests: %v\n", result.Coverage)
	if len(result.Owners) > 0 {
		fmt.Fprintf(b, "Owners: %s\n", strings.Join(result.Owners, ", "))
	} else {
		fmt.Fprintf(b, "Owners: (unowned)\n")
	}
}

// formatSymbolSection writes the symbol-specific portion of the text report.
func formatSymbolSection(b *strings.Builder, result *inspectResult) {
	fmt.Fprintf(b, "Symbol: %s\n", result.Target)
	fmt.Fprintf(b, "Health: %d/100 (grade: %s)\n", result.HealthScore, result.Grade)
	formatSymbolList(b, "\nDirect Callers", result.DirectCallers, "none (entry point)")
	formatSymbolList(b, "\nDirect Callees", result.DirectCallees, "none")
	formatCallChain(b, result.CallChain)
}

// formatSymbolList writes a labelled list of symbols with a fallback message.
func formatSymbolList(b *strings.Builder, label string, items []string, emptyMsg string) {
	if len(items) > 0 {
		fmt.Fprintf(b, "%s (%d):\n", label, len(items))
		for _, c := range items {
			fmt.Fprintf(b, "  → %s\n", c)
		}
		return
	}
	fmt.Fprintf(b, "%s: %s\n", label, emptyMsg)
}

// formatCallChain writes the call chain with indentation.
func formatCallChain(b *strings.Builder, chain []string) {
	if len(chain) == 0 {
		return
	}
	fmt.Fprintf(b, "\nCall Chain:\n")
	for i, c := range chain {
		indent := strings.Repeat("  ", i)
		fmt.Fprintf(b, "%s→ %s\n", indent, c)
	}
}

// formatFindingsSection writes the findings portion of the text report.
func formatFindingsSection(b *strings.Builder, result *inspectResult) {
	if len(result.Findings) > 0 {
		fmt.Fprintf(b, "\nFindings (%d):\n", len(result.Findings))
		for _, f := range result.Findings {
			fmt.Fprintf(b, "  %s %s:%d  %s\n", f.Severity, f.File, f.Line, f.Message)
		}
	} else {
		fmt.Fprintf(b, "\nFindings: none\n")
	}
}

// FormatInspectJSON renders an inspect result as JSON.
//gollaw:ignore thin-wrappers
func FormatInspectJSON(result *inspectResult) ([]byte, error) {
	return json.MarshalIndent(result, "", "  ")
}

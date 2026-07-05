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
	"github.com/dovocoder/gollaw/internal/reporter"
	"github.com/dovocoder/gollaw/internal/trace"
)

// InspectTarget represents the target of inspection: either a file path or
// a symbol name.
//gollaw:keep
type InspectTarget struct {
	Value string
	IsFile bool
}

// FileIdentity holds basic identity information about a file.
//gollaw:keep
type FileIdentity struct {
	Path      string `json:"path"`
	Package   string `json:"package"`
	LineCount int    `json:"lineCount"`
	FuncCount int    `json:"funcCount"`
}

// InspectResult holds the result of inspecting a file or symbol.
//gollaw:keep
type InspectResult struct {
	Target         string           `json:"target"`
	Kind           string           `json:"kind"` // "file" or "symbol"
	FileIdentity   FileIdentity     `json:"fileIdentity,omitempty"`
	Findings       []analyzer.Finding `json:"findings"`
	HealthScore    int              `json:"healthScore"`
	Grade          string           `json:"grade"`
	CallChain      []string         `json:"callChain,omitempty"`
	DirectCallers  []string         `json:"directCallers,omitempty"`
	DirectCallees  []string         `json:"directCallees,omitempty"`
	Coverage       bool             `json:"coverage"`
	Owners         []string         `json:"owners,omitempty"`
}

// Inspect analyses a target (file path or symbol name) and returns a detailed
// inspection result. The ctx parameter provides the loaded codebase context.
// If target looks like a file path (contains "/" or ends with ".go"), it is
// treated as a file; otherwise as a symbol name.
func Inspect(ctx *analyzer.Context, target string, dir string) (*InspectResult, error) {
	isFile := strings.Contains(target, "/") || strings.HasSuffix(target, ".go")
	if isFile {
		return inspectFile(ctx, target, dir)
	}
	return inspectSymbol(ctx, target, dir)
}

// inspectFile analyses a single file.
func inspectFile(ctx *analyzer.Context, filePath string, dir string) (*InspectResult, error) {
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		absPath = filePath
	}

	// Find the file in loaded packages and gather identity info.
	identity := FileIdentity{Path: filePath}

	for pPath, files := range ctx.SyntaxByPkg {
		for _, file := range files {
			pos := ctx.FSET.Position(file.Pos())
			if pos.Filename == absPath || pos.Filename == filePath {
				identity.Package = pPath
				// Count lines.
				if fileEnd := ctx.FSET.Position(file.End()); fileEnd.Line > 0 {
					identity.LineCount = fileEnd.Line
				}
				// Count functions.
				var funcCount int
				for _, decl := range file.Decls {
					if _, ok := decl.(*ast.FuncDecl); ok {
						funcCount++
					}
				}
				identity.FuncCount = funcCount
				break
			}
		}
		if identity.Package != "" {
			break
		}
	}

	// Run analyzers to get findings.
	var allFindings []analyzer.Finding
	registry := analyzer.NewRegistry()
	for _, a := range registry.All() {
		findings, err := a.Analyze(ctx)
		if err != nil {
			continue
		}
		allFindings = append(allFindings, findings...)
	}

	// Filter findings to this file.
	var fileFindings []analyzer.Finding
	for _, f := range allFindings {
		if f.File == filePath || f.File == absPath || strings.HasSuffix(f.File, filePath) {
			fileFindings = append(fileFindings, f)
		}
	}

	// Compute health score from filtered findings.
	healthScore, grade := computeFileHealth(fileFindings)

	// Check for test coverage (look for _test.go file).
	coverage := hasTestFile(absPath)

	// Look up owners from CODEOWNERS.
	owners := lookupOwners(filePath, dir)

	return &InspectResult{
		Target:       filePath,
		Kind:         "file",
		FileIdentity: identity,
		Findings:     fileFindings,
		HealthScore:  healthScore,
		Grade:        grade,
		Coverage:     coverage,
		Owners:       owners,
	}, nil
}

// inspectSymbol analyses a symbol (function/method) by name.
func inspectSymbol(ctx *analyzer.Context, symbol string, dir string) (*InspectResult, error) {
	// Trace callers and callees.
	callersResult, err := trace.TraceCallers(ctx, symbol, 1)
	var directCallers []string
	if err == nil && callersResult != nil {
		for _, chain := range callersResult.Chains {
			if len(chain) > 1 {
				directCallers = append(directCallers, chain[0].Function)
			}
		}
	}

	calleesResult, err := trace.TraceCallees(ctx, symbol, 1)
	var directCallees []string
	var callChain []string
	if err == nil && calleesResult != nil {
		for _, chain := range calleesResult.Chains {
			if len(chain) > 1 {
				directCallees = append(directCallees, chain[1].Function)
			}
			for _, node := range chain {
				callChain = append(callChain, node.Function)
			}
		}
	}

	// Run analyzers to get findings.
	var allFindings []analyzer.Finding
	registry := analyzer.NewRegistry()
	for _, a := range registry.All() {
		findings, err := a.Analyze(ctx)
		if err != nil {
			continue
		}
		allFindings = append(allFindings, findings...)
	}

	// Filter findings that mention the symbol.
	var symbolFindings []analyzer.Finding
	for _, f := range allFindings {
		if strings.Contains(f.Message, symbol) || strings.Contains(f.Detail, symbol) {
			symbolFindings = append(symbolFindings, f)
		}
	}

	healthScore, grade := computeFileHealth(symbolFindings)

	return &InspectResult{
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

	grade := "F"
	switch {
	case score >= 90:
		grade = "A"
	case score >= 80:
		grade = "B"
	case score >= 70:
		grade = "C"
	case score >= 60:
		grade = "D"
	case score >= 50:
		grade = "E"
	}

	return score, grade
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
func FormatInspectText(result *InspectResult) string {
	var b strings.Builder

	fmt.Fprintf(&b, "Inspection: %s (%s)\n", result.Target, result.Kind)
	fmt.Fprintf(&b, "%s\n", strings.Repeat("─", 50))

	if result.Kind == "file" {
		fmt.Fprintf(&b, "File: %s\n", result.FileIdentity.Path)
		fmt.Fprintf(&b, "Package: %s\n", result.FileIdentity.Package)
		fmt.Fprintf(&b, "Lines: %d  |  Functions: %d\n", result.FileIdentity.LineCount, result.FileIdentity.FuncCount)
		fmt.Fprintf(&b, "Health: %d/100 (grade: %s)\n", result.HealthScore, result.Grade)
		fmt.Fprintf(&b, "Has tests: %v\n", result.Coverage)
		if len(result.Owners) > 0 {
			fmt.Fprintf(&b, "Owners: %s\n", strings.Join(result.Owners, ", "))
		} else {
			fmt.Fprintf(&b, "Owners: (unowned)\n")
		}
	} else {
		fmt.Fprintf(&b, "Symbol: %s\n", result.Target)
		fmt.Fprintf(&b, "Health: %d/100 (grade: %s)\n", result.HealthScore, result.Grade)
		if len(result.DirectCallers) > 0 {
			fmt.Fprintf(&b, "\nDirect Callers (%d):\n", len(result.DirectCallers))
			for _, c := range result.DirectCallers {
				fmt.Fprintf(&b, "  → %s\n", c)
			}
		} else {
			fmt.Fprintf(&b, "\nDirect Callers: none (entry point)\n")
		}
		if len(result.DirectCallees) > 0 {
			fmt.Fprintf(&b, "\nDirect Callees (%d):\n", len(result.DirectCallees))
			for _, c := range result.DirectCallees {
				fmt.Fprintf(&b, "  → %s\n", c)
			}
		}
		if len(result.CallChain) > 0 {
			fmt.Fprintf(&b, "\nCall Chain:\n")
			for i, c := range result.CallChain {
				indent := strings.Repeat("  ", i)
				fmt.Fprintf(&b, "%s→ %s\n", indent, c)
			}
		}
	}

	if len(result.Findings) > 0 {
		fmt.Fprintf(&b, "\nFindings (%d):\n", len(result.Findings))
		for _, f := range result.Findings {
			fmt.Fprintf(&b, "  %s %s:%d  %s\n", f.Severity, f.File, f.Line, f.Message)
		}
	} else {
		fmt.Fprintf(&b, "\nFindings: none\n")
	}

	return b.String()
}

// FormatInspectJSON renders an inspect result as JSON.
func FormatInspectJSON(result *InspectResult) ([]byte, error) {
	return json.MarshalIndent(result, "", "  ")
}

// computeFileHealthFromReport is a helper that computes health from a reporter
// report's health score. This is used when the inspect package needs to
// reference the reporter's health computation.
func computeFileHealthFromReport(rep *reporter.Report) (int, string) {
	if rep == nil {
		return 100, "A"
	}
	return rep.HealthScore.Score, rep.HealthScore.Grade
}

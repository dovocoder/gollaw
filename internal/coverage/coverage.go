package coverage

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/dovocoder/gollaw/internal/analyzer"
)

// CoverageGap describes a function that lacks test coverage.
//gollaw:keep
type CoverageGap struct {
	Function   string `json:"function"`
	File       string `json:"file"`
	Line       int    `json:"line"`
	Package    string `json:"package"`
	HasTestFile bool   `json:"hasTestFile"`
}

// CoverageReport summarises test coverage gaps across the codebase.
//gollaw:keep
type CoverageReport struct {
	TotalFunctions   int            `json:"totalFunctions"`
	TestedFunctions  int            `json:"testedFunctions"`
	UntestedFunctions int           `json:"untestedFunctions"`
	CoveragePercent  float64        `json:"coveragePercent"`
	Gaps             []CoverageGap  `json:"gaps"`
}

// AnalyzeCoverage finds functions with no corresponding test coverage.
func AnalyzeCoverage(ctx *analyzer.Context) (*CoverageReport, error) {
	if ctx == nil {
		return nil, fmt.Errorf("nil analyzer context")
	}

	// Collect all non-test functions from loaded packages.
	type fnInfo struct {
		name    string
		pkgPath string
		file    string
		line    int
	}

	var allFns []fnInfo
	testFuncNames := make(map[string]bool) // "pkgPath.TestName" → true
	calledFromTests := make(map[string]bool) // "pkgPath.FuncName" → true

	for _, pkg := range ctx.Packages {
		if pkg.Types == nil || len(pkg.Syntax) == 0 {
			continue
		}
		pkgPath := pkg.PkgPath

		for _, file := range pkg.Syntax {
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok {
					continue
				}
				// Skip methods' receiver-only? No — include methods too.
				funcName := fn.Name.Name

				// Is this a test function?
				if isTestFuncName(funcName) {
					testFuncNames[pkgPath+"."+funcName] = true

					// Record which functions this test calls.
					calledFns := collectCalledFuncs(file, fn)
					for _, called := range calledFns {
						calledFromTests[pkgPath+"."+called] = true
					}
				}

				// Skip init, main (always "covered" conceptually).
				if funcName == "init" || funcName == "main" {
					continue
				}

				// Skip test helper functions.
				if isTestFuncName(funcName) || strings.HasPrefix(funcName, "test") || strings.HasPrefix(funcName, "Test") {
					continue
				}

				pos := ctx.FSET.Position(fn.Pos())
				allFns = append(allFns, fnInfo{
					name:    funcName,
					pkgPath: pkgPath,
					file:    pos.Filename,
					line:    pos.Line,
				})
			}
		}
	}

	// Determine which packages have _test.go files on disk.
	pkgHasTestFile := make(map[string]bool)
	for _, fn := range allFns {
		if pkgHasTestFile[fn.pkgPath] {
			continue
		}
		dir := filepath.Dir(fn.file)
		pkgHasTestFile[fn.pkgPath] = dirHasTestFiles(dir)
	}

	report := &CoverageReport{
		TotalFunctions: len(allFns),
	}

	for _, fn := range allFns {
		tested := isTested(fn.name, fn.pkgPath, testFuncNames, calledFromTests)
		if tested {
			report.TestedFunctions++
		} else {
			report.UntestedFunctions++
			report.Gaps = append(report.Gaps, CoverageGap{
				Function:   fn.name,
				File:       fn.file,
				Line:       fn.line,
				Package:    fn.pkgPath,
				HasTestFile: pkgHasTestFile[fn.pkgPath],
			})
		}
	}

	if report.TotalFunctions > 0 {
		report.CoveragePercent = float64(report.TestedFunctions) / float64(report.TotalFunctions) * 100
	}

	sort.Slice(report.Gaps, func(i, j int) bool {
		if report.Gaps[i].Package != report.Gaps[j].Package {
			return report.Gaps[i].Package < report.Gaps[j].Package
		}
		return report.Gaps[i].Line < report.Gaps[j].Line
	})

	return report, nil
}

// FormatCoverageText renders the coverage report as a human-readable table.
func FormatCoverageText(report *CoverageReport) string {
	if report == nil {
		return ""
	}
	var b strings.Builder

	fmt.Fprintf(&b, "Coverage Report\n")
	fmt.Fprintf(&b, "===============\n\n")
	fmt.Fprintf(&b, "Total functions:   %d\n", report.TotalFunctions)
	fmt.Fprintf(&b, "Tested functions:  %d\n", report.TestedFunctions)
	fmt.Fprintf(&b, "Untested functions: %d\n", report.UntestedFunctions)
	fmt.Fprintf(&b, "Coverage:          %.1f%%\n\n", report.CoveragePercent)

	if len(report.Gaps) > 0 {
		fmt.Fprintf(&b, "Coverage Gaps\n")
		fmt.Fprintf(&b, "%-30s  %-40s  %-8s  %s\n", "FUNCTION", "PACKAGE", "HAS TEST", "FILE:LINE")
		fmt.Fprintf(&b, "%s\n", strings.Repeat("-", 100))
		for _, g := range report.Gaps {
			hasTest := "no"
			if g.HasTestFile {
				hasTest = "yes"
			}
			fmt.Fprintf(&b, "%-30.30s  %-40.40s  %-8s  %s:%d\n", g.Function, g.Package, hasTest, g.File, g.Line)
		}
	}

	return b.String()
}

// FormatCoverageJSON renders the coverage report as JSON.
func FormatCoverageJSON(report *CoverageReport) ([]byte, error) {
	if report == nil {
		return []byte("null"), nil
	}
	return json.MarshalIndent(report, "", "  ")
}

// --- helpers ---

// isTestFuncName returns true if the name follows Go test naming conventions.
func isTestFuncName(name string) bool {
	return strings.HasPrefix(name, "Test") ||
		strings.HasPrefix(name, "Benchmark") ||
		strings.HasPrefix(name, "Fuzz") ||
		name == "TestMain"
}

// isTested checks whether a function has a corresponding test or is called
// from any test function in the same package.
func isTested(funcName, pkgPath string, testFuncs map[string]bool, calledFromTests map[string]bool) bool {
	// (a) Is there a TestFuncName test?
	if testFuncs[pkgPath+".Test"+funcName] {
		return true
	}
	// (b) Is the function called from any test function?
	if calledFromTests[pkgPath+"."+funcName] {
		return true
	}
	return false
}

// collectCalledFuncs walks the body of a test function and collects the names
// of functions it calls.
func collectCalledFuncs(file *ast.File, fn *ast.FuncDecl) []string {
	var called []string
	if fn.Body == nil {
		return called
	}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fun := call.Fun.(type) {
		case *ast.Ident:
			called = append(called, fun.Name)
		case *ast.SelectorExpr:
			if fun.Sel != nil {
				called = append(called, fun.Sel.Name)
			}
		}
		return true
	})
	return called
}

// dirHasTestFiles checks whether the directory contains any _test.go files.
func dirHasTestFiles(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), "_test.go") {
			return true
		}
	}
	return false
}

// Unused imports — kept for potential future use with types.Info.
// (removed unused var declarations)

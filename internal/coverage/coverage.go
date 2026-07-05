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

// coverageGap describes a function that lacks test coverage.
type coverageGap struct {
	Function   string `json:"function"`
	File       string `json:"file"`
	Line       int    `json:"line"`
	Package    string `json:"package"`
	HasTestFile bool   `json:"hasTestFile"`
}

// coverageReport summarises test coverage gaps across the codebase.
type coverageReport struct {
	TotalFunctions   int           `json:"totalFunctions"`
	TestedFunctions  int           `json:"testedFunctions"`
	UntestedFunctions int          `json:"untestedFunctions"`
	CoveragePercent  float64       `json:"coveragePercent"`
	Gaps             []coverageGap `json:"gaps"`
}

// fnInfo holds metadata about a non-test function found in the codebase.
type fnInfo struct {
	name    string
	pkgPath string
	file    string
	line    int
}

// AnalyzeCoverage finds functions with no corresponding test coverage.
func AnalyzeCoverage(ctx *analyzer.Context) (*coverageReport, error) {
	if ctx == nil {
		return nil, fmt.Errorf("nil analyzer context")
	}

	allFns, testFuncNames, calledFromTests := collectFunctions(ctx)
	pkgHasTestFile := detectTestFiles(allFns)
	return buildReport(allFns, testFuncNames, calledFromTests, pkgHasTestFile)
}

// collectFunctions gathers all non-test functions and test call information.
func collectFunctions(ctx *analyzer.Context) ([]fnInfo, map[string]bool, map[string]bool) {
	var allFns []fnInfo
	testFuncNames := make(map[string]bool)
	calledFromTests := make(map[string]bool)

	for _, pkg := range ctx.Packages {
		if pkg.Types == nil || len(pkg.Syntax) == 0 {
			continue
		}
		pkgPath := pkg.PkgPath
		for _, file := range pkg.Syntax {
			processFileDecls(file, pkgPath, ctx, &allFns, testFuncNames, calledFromTests)
		}
	}
	return allFns, testFuncNames, calledFromTests
}

// processFileDecls iterates declarations in a file, collecting functions and tests.
func processFileDecls(
	file *ast.File, pkgPath string, ctx *analyzer.Context,
	allFns *[]fnInfo, testFuncNames, calledFromTests map[string]bool,
) {
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		funcName := fn.Name.Name

		if isTestFuncName(funcName) {
			testFuncNames[pkgPath+"."+funcName] = true
			recordTestCalls(file, fn, pkgPath, calledFromTests)
		}
		if shouldSkipFunc(funcName) {
			continue
		}

		pos := ctx.FSET.Position(fn.Pos())
		*allFns = append(*allFns, fnInfo{
			name: funcName, pkgPath: pkgPath, file: pos.Filename, line: pos.Line,
		})
	}
}

// recordTestCalls records which functions a test function calls.
func recordTestCalls(file *ast.File, fn *ast.FuncDecl, pkgPath string, calledFromTests map[string]bool) {
	calledFns := collectCalledFuncs(file, fn)
	for _, called := range calledFns {
		calledFromTests[pkgPath+"."+called] = true
	}
}

// shouldSkipFunc returns true for init, main, and test-related functions.
func shouldSkipFunc(funcName string) bool {
	if funcName == "init" || funcName == "main" {
		return true
	}
	if isTestFuncName(funcName) {
		return true
	}
	return strings.HasPrefix(funcName, "test") || strings.HasPrefix(funcName, "Test")
}

// detectTestFiles determines which packages have _test.go files on disk.
func detectTestFiles(allFns []fnInfo) map[string]bool {
	pkgHasTestFile := make(map[string]bool)
	for _, fn := range allFns {
		if pkgHasTestFile[fn.pkgPath] {
			continue
		}
		dir := filepath.Dir(fn.file)
		pkgHasTestFile[fn.pkgPath] = dirHasTestFiles(dir)
	}
	return pkgHasTestFile
}

// buildReport constructs the coverage report from collected data.
func buildReport(
	allFns []fnInfo, testFuncNames, calledFromTests map[string]bool,
	pkgHasTestFile map[string]bool,
) (*coverageReport, error) {
	report := &coverageReport{TotalFunctions: len(allFns)}

	for _, fn := range allFns {
		tested := isTested(fn.name, fn.pkgPath, testFuncNames, calledFromTests)
		if tested {
			report.TestedFunctions++
		} else {
			report.UntestedFunctions++
			report.Gaps = append(report.Gaps, coverageGap{
				Function:    fn.name,
				File:        fn.file,
				Line:        fn.line,
				Package:     fn.pkgPath,
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
func FormatCoverageText(report *coverageReport) string {
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
func FormatCoverageJSON(report *coverageReport) ([]byte, error) {
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

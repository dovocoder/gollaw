// Package regression provides baseline comparison with tolerance for
// detecting regressions in codebase quality over time.
package regression

import (
	"fmt"
	"strings"

	"github.com/dovocoder/gollaw/internal/analyzer"
	"github.com/dovocoder/gollaw/internal/baseline"
	"github.com/dovocoder/gollaw/internal/loader"
)

// RegressionResult holds the result of a regression check.
type RegressionResult struct {
	BaselineCount   int            `json:"baselineCount"`
	CurrentCount    int            `json:"currentCount"`
	Delta           int            `json:"delta"`
	WithinTolerance bool           `json:"withinTolerance"`
	Tolerance       int            `json:"tolerance"`
	ByCategory      map[string]int `json:"byCategory"`
	Outcome         string         `json:"outcome"` // pass, fail, warn
}

// RunRegression loads the baseline, runs current analysis, and compares.
// If the current finding count exceeds the baseline by more than tolerance,
// the outcome is "fail". If it exceeds but within tolerance, outcome is "warn".
// Otherwise the outcome is "pass".
func RunRegression(dir string, tolerance int) (*RegressionResult, error) {
	// Load baseline.
	baselineFindings, err := baseline.Load(dir)
	if err != nil {
		return nil, fmt.Errorf("load baseline: %w", err)
	}

	// Run current analysis.
	result, err := loader.Load(loader.LoadConfig{Patterns: []string{"./..."}, Dir: dir})
	if err != nil {
		return nil, fmt.Errorf("load codebase: %w", err)
	}

	ctx := &analyzer.Context{
		FSET:        result.FSET,
		Packages:    result.Packages,
		SSA:         result.SSA,
		SSAByPkg:    result.SSAByPkg,
		TypesByPkg:  result.TypesByPkg,
		SyntaxByPkg: result.SyntaxByPkg,
	}

	var currentFindings []analyzer.Finding
	registry := analyzer.NewRegistry()
	for _, a := range registry.All() {
		findings, err := a.Analyze(ctx)
		if err != nil {
			continue
		}
		currentFindings = append(currentFindings, findings...)
	}

	// Compute result.
	regResult := &RegressionResult{
		BaselineCount: len(baselineFindings),
		CurrentCount:  len(currentFindings),
		Tolerance:     tolerance,
		ByCategory:    make(map[string]int),
	}

	regResult.Delta = regResult.CurrentCount - regResult.BaselineCount

	// Determine outcome.
	if regResult.Delta > tolerance {
		regResult.Outcome = "fail"
		regResult.WithinTolerance = false
	} else if regResult.Delta > 0 {
		regResult.Outcome = "warn"
		regResult.WithinTolerance = true
	} else {
		regResult.Outcome = "pass"
		regResult.WithinTolerance = true
	}

	// Break down delta by category.
	baselineByCategory := countByCategory(baselineFindings)
	currentByCategory := countByCategory(currentFindings)

	allCategories := make(map[string]bool)
	for cat := range baselineByCategory {
		allCategories[cat] = true
	}
	for cat := range currentByCategory {
		allCategories[cat] = true
	}
	for cat := range allCategories {
		delta := currentByCategory[cat] - baselineByCategory[cat]
		if delta != 0 {
			regResult.ByCategory[cat] = delta
		}
	}

	return regResult, nil
}

// countByCategory groups findings by category and returns counts.
func countByCategory(findings []analyzer.Finding) map[string]int {
	counts := make(map[string]int)
	for _, f := range findings {
		counts[string(f.Category)]++
	}
	return counts
}

// FormatRegressionText renders a regression result as human-readable text.
func FormatRegressionText(result *RegressionResult) string {
	var b strings.Builder

	fmt.Fprintf(&b, "Regression Check\n")
	fmt.Fprintf(&b, "%s\n", strings.Repeat("─", 50))
	fmt.Fprintf(&b, "Baseline: %d findings\n", result.BaselineCount)
	fmt.Fprintf(&b, "Current:  %d findings\n", result.CurrentCount)
	fmt.Fprintf(&b, "Delta:    %+d\n", result.Delta)
	fmt.Fprintf(&b, "Tolerance: %d\n", result.Tolerance)

	// Outcome with icon.
	var icon string
	switch result.Outcome {
	case "pass":
		icon = "✅"
	case "warn":
		icon = "⚠️"
	case "fail":
		icon = "❌"
	default:
		icon = "•"
	}
	fmt.Fprintf(&b, "Outcome: %s %s\n", icon, strings.ToUpper(result.Outcome))

	if len(result.ByCategory) > 0 {
		fmt.Fprintf(&b, "\nBy Category:\n")
		for cat, delta := range result.ByCategory {
			sign := "+"
			if delta < 0 {
				sign = ""
			}
			fmt.Fprintf(&b, "  %-20s %s%d\n", cat, sign, delta)
		}
	}

	if !result.WithinTolerance {
		fmt.Fprintf(&b, "\n⚠ Regression detected: %d new findings exceed tolerance of %d\n", result.Delta, result.Tolerance)
	}

	return b.String()
}

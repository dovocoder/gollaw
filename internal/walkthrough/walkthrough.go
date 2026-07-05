// Package walkthrough provides guided codebase walkthroughs that lead
// developers through findings in a structured, actionable order.
package walkthrough

import (
	"fmt"
	"strings"

	"github.com/dovocoder/gollaw/internal/analyzer"
	"github.com/dovocoder/gollaw/internal/reporter"
)

// walkthroughStep represents a single step in a guided walkthrough.
type walkthroughStep struct {
	Title       string             `json:"title"`
	Description string             `json:"description"`
	Findings    []analyzer.Finding `json:"findings"`
	Action      string             `json:"action"`
}

// walkthroughResult holds the complete guided walkthrough.
type walkthroughResult struct {
	Steps          []walkthroughStep `json:"steps"`
	TotalFindings  int               `json:"totalFindings"`
	EstimatedTime  string            `json:"estimatedTime"`
}

// appendStep adds a walkthrough step to the result if findings is non-empty.
func appendStep(steps []walkthroughStep, title, desc, action string, findings []analyzer.Finding) []walkthroughStep {
	if len(findings) == 0 {
		return steps
	}
	return append(steps, walkthroughStep{
		Title:       title,
		Description: desc,
		Findings:    findings,
		Action:      action,
	})
}

// GenerateWalkthrough creates a structured walkthrough from findings and
// codebase stats. Steps are ordered by priority and skip empty categories.
func GenerateWalkthrough(findings []analyzer.Finding, stats reporter.CodebaseStats) *walkthroughResult {
	healthScore := reporter.ScoreFromPenalty(reporter.ComputePenalty(findings))
	result := &walkthroughResult{Steps: []walkthroughStep{}}

	result.Steps = append(result.Steps, walkthroughStep{
		Title:       "Health Overview",
		Description: fmt.Sprintf("Codebase: %d packages, %d files, %d functions, %d types. Health score: %d/100 (grade: %s).",
			stats.Packages, stats.Files, stats.Functions, stats.Types, healthScore, computeGrade(healthScore)),
		Action: "Review the overall health score and identify areas for improvement.",
	})

	result.Steps = appendConditionalSteps(result.Steps, findings)

	result.Steps = append(result.Steps, walkthroughStep{
		Title:       "Next Steps",
		Description: "Recommendations for ongoing code quality improvement.",
		Action:      buildNextStepsAction(findings),
	})

	result.TotalFindings = len(findings)
	result.EstimatedTime = estimateTime(findings)
	return result
}

// appendConditionalSteps appends steps for critical, dead-code, complexity,
// duplication, and security findings — skipping empty categories.
func appendConditionalSteps(steps []walkthroughStep, findings []analyzer.Finding) []walkthroughStep {
	critical := filterBySeverity(findings, analyzer.SeverityCritical)
	steps = appendStep(steps, "Critical Issues",
		fmt.Sprintf("%d critical findings that should be addressed immediately.", len(critical)),
		"Fix critical issues before anything else — these may indicate bugs or security risks.",
		critical)

	deadCode := filterByAnalyzer(findings, "deadcode")
	steps = appendStep(steps, "Dead Code",
		fmt.Sprintf("%d unreachable functions detected.", len(deadCode)),
		"Remove dead code to reduce maintenance burden and improve clarity.",
		deadCode)

	complexity := filterByCategory(findings, analyzer.CategoryComplexity)
	steps = appendStep(steps, "Complexity Hotspots",
		fmt.Sprintf("%d functions with high cyclomatic or cognitive complexity.", len(complexity)),
		"Refactor complex functions — break them into smaller, focused units.",
		complexity)

	duplication := filterByCategory(findings, analyzer.CategoryDuplication)
	steps = appendStep(steps, "Duplication",
		fmt.Sprintf("%d duplicate code blocks detected.", len(duplication)),
		"Extract duplicated logic into shared helpers or utilities.",
		duplication)

	security := filterByAnalyzer(findings, "security")
	steps = appendStep(steps, "Security Review",
		fmt.Sprintf("%d security-related findings.", len(security)),
		"Review security findings carefully and apply recommended mitigations.",
		security)

	return steps
}

// filterBySeverity returns findings matching the given severity.
func filterBySeverity(findings []analyzer.Finding, sev analyzer.Severity) []analyzer.Finding {
	var result []analyzer.Finding
	for _, f := range findings {
		if f.Severity == sev {
			result = append(result, f)
		}
	}
	return result
}

// filterByAnalyzer returns findings from the given analyzer.
func filterByAnalyzer(findings []analyzer.Finding, name string) []analyzer.Finding {
	var result []analyzer.Finding
	for _, f := range findings {
		if f.Analyzer == name {
			result = append(result, f)
		}
	}
	return result
}

// filterByCategory returns findings matching the given category.
func filterByCategory(findings []analyzer.Finding, cat analyzer.Category) []analyzer.Finding {
	var result []analyzer.Finding
	for _, f := range findings {
		if f.Category == cat {
			result = append(result, f)
		}
	}
	return result
}

// computeGrade converts a score to a letter grade.
func computeGrade(score int) string {
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

// buildNextStepsAction creates actionable recommendations.
func buildNextStepsAction(findings []analyzer.Finding) string {
	var steps []string

	critical := len(filterBySeverity(findings, analyzer.SeverityCritical))
	warnings := len(filterBySeverity(findings, analyzer.SeverityWarning))
	deadcode := len(filterByAnalyzer(findings, "deadcode"))

	if critical > 0 {
		steps = append(steps, fmt.Sprintf("- Resolve %d critical issue(s) first", critical))
	}
	if deadcode > 0 {
		steps = append(steps, fmt.Sprintf("- Remove %d dead code item(s)", deadcode))
	}
	if warnings > 0 {
		steps = append(steps, fmt.Sprintf("- Address %d warning(s) in the next sprint", warnings))
	}
	steps = append(steps, "- Run `gollaw baseline save` to establish a quality baseline")
	steps = append(steps, "- Set up `gollaw watch` for continuous monitoring")

	return strings.Join(steps, "\n")
}

// estimateTime estimates the time needed to address all findings.
// 5 min per critical, 2 min per warning, 1 min per info.
func estimateTime(findings []analyzer.Finding) string {
	minutes := 0
	for _, f := range findings {
		switch f.Severity {
		case analyzer.SeverityCritical:
			minutes += 5
		case analyzer.SeverityWarning:
			minutes += 2
		case analyzer.SeverityInfo:
			minutes += 1
		case analyzer.SeverityHint:
			minutes += 1
		}
	}

	hours := minutes / 60
	mins := minutes % 60

	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, mins)
	}
	return fmt.Sprintf("%dm", minutes)
}

// FormatWalkthroughText renders a walkthrough result as human-readable text.
func FormatWalkthroughText(result *walkthroughResult) string {
	var b strings.Builder

	fmt.Fprintf(&b, "Guided Codebase Walkthrough\n")
	fmt.Fprintf(&b, "%s\n", strings.Repeat("═", 50))
	fmt.Fprintf(&b, "Total findings: %d  |  Estimated time: %s\n", result.TotalFindings, result.EstimatedTime)
	fmt.Fprintf(&b, "%s\n\n", strings.Repeat("═", 50))

	for i, step := range result.Steps {
		fmt.Fprintf(&b, "Step %d: %s\n", i+1, step.Title)
		fmt.Fprintf(&b, "%s\n", strings.Repeat("─", 40))
		fmt.Fprintf(&b, "%s\n", step.Description)

		if len(step.Findings) > 0 {
			fmt.Fprintf(&b, "\nFindings:\n")
			for _, f := range step.Findings {
				fmt.Fprintf(&b, "  %s %s:%d  %s\n", f.Severity, f.File, f.Line, f.Message)
			}
		}

		fmt.Fprintf(&b, "\n→ Action: %s\n", step.Action)
		fmt.Fprintf(&b, "\n")
	}

	return b.String()
}

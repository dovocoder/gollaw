// Package walkthrough provides guided codebase walkthroughs that lead
// developers through findings in a structured, actionable order.
package walkthrough

import (
	"fmt"
	"strings"

	"github.com/dovocoder/gollaw/internal/analyzer"
	"github.com/dovocoder/gollaw/internal/reporter"
)

// WalkthroughStep represents a single step in a guided walkthrough.
type WalkthroughStep struct {
	Title       string              `json:"title"`
	Description string              `json:"description"`
	Findings    []analyzer.Finding  `json:"findings"`
	Action      string              `json:"action"`
}

// WalkthroughResult holds the complete guided walkthrough.
type WalkthroughResult struct {
	Steps         []WalkthroughStep `json:"steps"`
	TotalFindings int               `json:"totalFindings"`
	EstimatedTime string            `json:"estimatedTime"`
}

// GenerateWalkthrough creates a structured walkthrough from findings and
// codebase stats. Steps are ordered by priority and skip empty categories.
func GenerateWalkthrough(findings []analyzer.Finding, stats reporter.CodebaseStats) *WalkthroughResult {
	result := &WalkthroughResult{
		Steps: []WalkthroughStep{},
	}

	// Step 1: Health Overview — always included.
	healthScore := computeHealthScore(findings)
	grade := computeGrade(healthScore)
	result.Steps = append(result.Steps, WalkthroughStep{
		Title:       "Health Overview",
		Description: fmt.Sprintf("Codebase: %d packages, %d files, %d functions, %d types. Health score: %d/100 (grade: %s).", stats.Packages, stats.Files, stats.Functions, stats.Types, healthScore, grade),
		Findings:    nil,
		Action:      "Review the overall health score and identify areas for improvement.",
	})

	// Step 2: Critical Issues — all critical findings.
	criticalFindings := filterBySeverity(findings, analyzer.SeverityCritical)
	if len(criticalFindings) > 0 {
		result.Steps = append(result.Steps, WalkthroughStep{
			Title:       "Critical Issues",
			Description: fmt.Sprintf("%d critical findings that should be addressed immediately.", len(criticalFindings)),
			Findings:    criticalFindings,
			Action:      "Fix critical issues before anything else — these may indicate bugs or security risks.",
		})
	}

	// Step 3: Dead Code — deadcode findings.
	deadCodeFindings := filterByAnalyzer(findings, "deadcode")
	if len(deadCodeFindings) > 0 {
		result.Steps = append(result.Steps, WalkthroughStep{
			Title:       "Dead Code",
			Description: fmt.Sprintf("%d unreachable functions detected.", len(deadCodeFindings)),
			Findings:    deadCodeFindings,
			Action:      "Remove dead code to reduce maintenance burden and improve clarity.",
		})
	}

	// Step 4: Complexity Hotspots — complexity findings.
	complexityFindings := filterByCategory(findings, analyzer.CategoryComplexity)
	if len(complexityFindings) > 0 {
		result.Steps = append(result.Steps, WalkthroughStep{
			Title:       "Complexity Hotspots",
			Description: fmt.Sprintf("%d functions with high cyclomatic or cognitive complexity.", len(complexityFindings)),
			Findings:    complexityFindings,
			Action:      "Refactor complex functions — break them into smaller, focused units.",
		})
	}

	// Step 5: Duplication — duplication findings.
	duplicationFindings := filterByCategory(findings, analyzer.CategoryDuplication)
	if len(duplicationFindings) > 0 {
		result.Steps = append(result.Steps, WalkthroughStep{
			Title:       "Duplication",
			Description: fmt.Sprintf("%d duplicate code blocks detected.", len(duplicationFindings)),
			Findings:    duplicationFindings,
			Action:      "Extract duplicated logic into shared helpers or utilities.",
		})
	}

	// Step 6: Security Review — security findings.
	securityFindings := filterByAnalyzer(findings, "security")
	if len(securityFindings) > 0 {
		result.Steps = append(result.Steps, WalkthroughStep{
			Title:       "Security Review",
			Description: fmt.Sprintf("%d security-related findings.", len(securityFindings)),
			Findings:    securityFindings,
			Action:      "Review security findings carefully and apply recommended mitigations.",
		})
	}

	// Step 7: Next Steps — always included.
	nextStepsAction := buildNextStepsAction(findings)
	result.Steps = append(result.Steps, WalkthroughStep{
		Title:       "Next Steps",
		Description: "Recommendations for ongoing code quality improvement.",
		Findings:    nil,
		Action:      nextStepsAction,
	})

	result.TotalFindings = len(findings)
	result.EstimatedTime = estimateTime(findings)

	return result
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

// computeHealthScore replicates the reporter's health score computation.
func computeHealthScore(findings []analyzer.Finding) int {
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
	return score
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
func FormatWalkthroughText(result *WalkthroughResult) string {
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

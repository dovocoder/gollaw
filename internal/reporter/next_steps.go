package reporter

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/dovocoder/gollaw/internal/analyzer"
)

// NextStep is an actionable recommendation derived from findings.
//gollaw:keep
type NextStep struct {
	Action      string `json:"action"`
	Priority    string `json:"priority"`
	Count       int    `json:"count"`
	Description string `json:"description"`
}

// FormatNextSteps renders actionable next-step recommendations as a JSON array.
// At most 5 steps are returned, sorted by priority (critical > high > medium > low).
//gollaw:keep
func FormatNextSteps(report *Report) ([]byte, error) {
	categoryCounts := make(map[string]int)
	for _, f := range report.Findings {
		categoryCounts[string(f.Category)]++
	}

	var steps []NextStep

	// Dead code → suggest running fix.
	if n := categoryCounts[string(analyzer.CategoryDeadCode)]; n > 0 {
		steps = append(steps, NextStep{
			Action:      "gollaw fix --analyzer deadcode",
			Priority:    "high",
			Count:       n,
			Description: fmt.Sprintf("Remove %d unreachable functions", n),
		})
	}

	// Unused dependencies → go mod tidy.
	if n := countByCategoryOrKeyword(categoryCounts, "dependencies", "unused-deps"); n > 0 {
		steps = append(steps, NextStep{
			Action:      "go mod tidy",
			Priority:    "medium",
			Count:       n,
			Description: fmt.Sprintf("Clean up %d unused dependency issues", n),
		})
	}

	// Complexity → refactor.
	if n := categoryCounts[string(analyzer.CategoryComplexity)]; n > 0 {
		steps = append(steps, NextStep{
			Action:      "refactor",
			Priority:    "high",
			Count:       n,
			Description: fmt.Sprintf("Refactor %d overly complex functions", n),
		})
	}

	// Duplication → extract.
	if n := categoryCounts[string(analyzer.CategoryDuplication)]; n > 0 {
		steps = append(steps, NextStep{
			Action:      "extract",
			Priority:    "medium",
			Count:       n,
			Description: fmt.Sprintf("Extract %d duplicated code blocks into shared helpers", n),
		})
	}

	// Security findings → review (matched by keyword since no dedicated category).
	if n := countSecurityFindings(report.Findings); n > 0 {
		steps = append(steps, NextStep{
			Action:      "review",
			Priority:    "critical",
			Count:       n,
			Description: fmt.Sprintf("Review and fix %d security-related findings", n),
		})
	}

	// Naming findings → fix (matched by keyword since no dedicated category).
	if n := countNamingFindings(report.Findings); n > 0 {
		steps = append(steps, NextStep{
			Action:      "gollaw fix --analyzer naming",
			Priority:    "low",
			Count:       n,
			Description: fmt.Sprintf("Auto-fix %d naming convention violations", n),
		})
	}

	// Sort by priority (critical > high > medium > low).
	sort.Slice(steps, func(i, j int) bool {
		return priorityRank(steps[i].Priority) < priorityRank(steps[j].Priority)
	})

	// Max 5 steps.
	if len(steps) > 5 {
		steps = steps[:5]
	}

	if steps == nil {
		steps = []NextStep{}
	}

	out, err := json.MarshalIndent(steps, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal next steps: %w", err)
	}
	return out, nil
}

func priorityRank(p string) int {
	switch p {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	default:
		return 4
	}
}

func countByCategoryOrKeyword(counts map[string]int, cat, keyword string) int {
	if n, ok := counts[cat]; ok {
		return n
	}
	if n, ok := counts[keyword]; ok {
		return n
	}
	return 0
}

func countSecurityFindings(findings []analyzer.Finding) int {
	count := 0
	for _, f := range findings {
		lc := strings.ToLower(string(f.Category))
		msg := strings.ToLower(f.Message)
		rule := strings.ToLower(f.RuleID)
		if strings.Contains(lc, "security") || strings.Contains(msg, "security") || strings.Contains(rule, "security") {
			count++
		}
	}
	return count
}

func countNamingFindings(findings []analyzer.Finding) int {
	count := 0
	for _, f := range findings {
		lc := strings.ToLower(string(f.Category))
		msg := strings.ToLower(f.Message)
		rule := strings.ToLower(f.RuleID)
		if strings.Contains(lc, "naming") || strings.Contains(msg, "naming") || strings.Contains(rule, "naming") {
			count++
		}
	}
	return count
}

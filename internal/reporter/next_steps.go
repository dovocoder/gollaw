package reporter

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/dovocoder/gollaw/internal/analyzer"
)

// nextStep is an actionable recommendation derived from findings.
type nextStep struct {
	Action      string `json:"action"`
	Priority    string `json:"priority"`
	Count       int    `json:"count"`
	Description string `json:"description"`
}

// formatNextSteps renders actionable next-step recommendations as a JSON array.
// At most 5 steps are returned, sorted by priority (critical > high > medium > low).
func formatNextSteps(report *Report) ([]byte, error) {
	categoryCounts := make(map[string]int)
	for _, f := range report.Findings {
		categoryCounts[string(f.Category)]++
	}

	steps := buildNextSteps(report.Findings, categoryCounts)
	sort.Slice(steps, func(i, j int) bool {
		return priorityRank(steps[i].Priority) < priorityRank(steps[j].Priority)
	})
	if len(steps) > 5 {
		steps = steps[:5]
	}
	if steps == nil {
		steps = []nextStep{}
	}

	out, err := json.MarshalIndent(steps, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal next steps: %w", err)
	}
	return out, nil
}

func buildNextSteps(findings []analyzer.Finding, counts map[string]int) []nextStep {
	var steps []nextStep

	steps = appendCategoryStep(steps, counts, string(analyzer.CategoryDeadCode), "high",
		"gollaw fix --analyzer deadcode", "Remove %d unreachable functions")
	steps = appendCategoryStep(steps, counts, string(analyzer.CategoryComplexity), "high",
		"refactor", "Refactor %d overly complex functions")
	steps = appendCategoryStep(steps, counts, string(analyzer.CategoryDuplication), "medium",
		"extract", "Extract %d duplicated code blocks into shared helpers")

	if n := countByCategoryOrKeyword(counts, "dependencies", "unused-deps"); n > 0 {
		steps = append(steps, nextStep{
			Action:      "go mod tidy",
			Priority:    "medium",
			Count:       n,
			Description: fmt.Sprintf("Clean up %d unused dependency issues", n),
		})
	}

	steps = appendKeywordStep(steps, findings, "security", "critical", "review",
		"Review and fix %d security-related findings")
	steps = appendKeywordStep(steps, findings, "naming", "low", "gollaw fix --analyzer naming",
		"Auto-fix %d naming convention violations")

	return steps
}

func appendCategoryStep(steps []nextStep, counts map[string]int, cat, priority, action, descFmt string) []nextStep {
	if n := counts[cat]; n > 0 {
		steps = append(steps, nextStep{
			Action:      action,
			Priority:    priority,
			Count:       n,
			Description: fmt.Sprintf(descFmt, n),
		})
	}
	return steps
}

func appendKeywordStep(steps []nextStep, findings []analyzer.Finding, keyword, priority, action, descFmt string) []nextStep {
	n := countKeywordFindings(findings, keyword)
	if n > 0 {
		steps = append(steps, nextStep{
			Action:      action,
			Priority:    priority,
			Count:       n,
			Description: fmt.Sprintf(descFmt, n),
		})
	}
	return steps
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

func countKeywordFindings(findings []analyzer.Finding, keyword string) int {
	count := 0
	for _, f := range findings {
		lc := strings.ToLower(string(f.Category))
		msg := strings.ToLower(f.Message)
		rule := strings.ToLower(f.RuleID)
		if strings.Contains(lc, keyword) || strings.Contains(msg, keyword) || strings.Contains(rule, keyword) {
			count++
		}
	}
	return count
}

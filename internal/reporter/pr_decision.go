package reporter

import (
	"encoding/json"
	"fmt"

	"github.com/dovocoder/gollaw/internal/analyzer"
)

// prGate is a single pass/fail gate in a PR decision.
type prGate struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Count  int    `json:"count"`
}

// prDecision is the machine-readable PR decision surface.
type prDecision struct {
	Schema       string         `json:"schema"`
	Conclusion   string         `json:"conclusion"`
	Gates        []prGate       `json:"gates"`
	Counts       map[string]int `json:"counts"`
	HealthScore  int            `json:"health_score"`
}

// healthThreshold is the default minimum health score for a passing gate.
const healthThreshold = 70

// formatPRDecision renders a structured PR decision with pass/fail gates.
func formatPRDecision(report *Report) ([]byte, error) {
	counts := buildSeverityCounts(report.Findings)
	gates := buildPRGates(report, counts)
	conclusion := determineConclusion(gates, counts["warning"])

	decision := prDecision{
		Schema:      "gollaw-pr-decision/v1",
		Conclusion:  conclusion,
		Gates:       gates,
		Counts:      counts,
		HealthScore: report.HealthScore.Score,
	}

	out, err := json.MarshalIndent(decision, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal pr-decision: %w", err)
	}
	return out, nil
}

func buildSeverityCounts(findings []analyzer.Finding) map[string]int {
	counts := map[string]int{
		"critical": 0,
		"warning":  0,
		"info":     0,
		"hint":     0,
		"total":    len(findings),
	}
	for _, f := range findings {
		counts[string(f.Severity)]++
	}
	return counts
}

func buildPRGates(report *Report, counts map[string]int) []prGate {
	var gates []prGate
	critCount := counts["critical"]
	gates = append(gates, prGate{
		Name:   "no-critical",
		Passed: critCount == 0,
		Count:  critCount,
	})
	gates = append(gates, prGate{
		Name:   "no-new-warnings",
		Passed: true,
		Count:  0,
	})
	gates = append(gates, prGate{
		Name:   "health-above-threshold",
		Passed: report.HealthScore.Score >= healthThreshold,
		Count:  healthThreshold,
	})
	return gates
}

func determineConclusion(gates []prGate, warningCount int) string {
	conclusion := "success"
	for _, g := range gates {
		if !g.Passed {
			return "failure"
		}
	}
	if warningCount > 0 {
		conclusion = "neutral"
	}
	return conclusion
}

// severityPriorityValue returns a numeric priority for sorting (lower = higher priority).
func severityPriorityValue(sev analyzer.Severity) int {
	switch sev {
	case analyzer.SeverityCritical:
		return 0
	case analyzer.SeverityWarning:
		return 1
	case analyzer.SeverityInfo:
		return 2
	case analyzer.SeverityHint:
		return 3
	default:
		return 4
	}
}

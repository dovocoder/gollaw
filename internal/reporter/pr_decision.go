package reporter

import (
	"encoding/json"
	"fmt"

	"github.com/dovocoder/gollaw/internal/analyzer"
)

// PRGate is a single pass/fail gate in a PR decision.
//gollaw:keep
type PRGate struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Count  int    `json:"count"`
}

// PRDecision is the machine-readable PR decision surface.
//gollaw:keep
type PRDecision struct {
	Schema       string         `json:"schema"`
	Conclusion   string         `json:"conclusion"`
	Gates        []PRGate       `json:"gates"`
	Counts       map[string]int `json:"counts"`
	HealthScore  int            `json:"health_score"`
}

// healthThreshold is the default minimum health score for a passing gate.
const healthThreshold = 70

// FormatPRDecision renders a structured PR decision with pass/fail gates.
//gollaw:keep
func FormatPRDecision(report *Report) ([]byte, error) {
	counts := map[string]int{
		"critical": 0,
		"warning":  0,
		"info":     0,
		"hint":     0,
		"total":    len(report.Findings),
	}
	for _, f := range report.Findings {
		counts[string(f.Severity)]++
	}

	var gates []PRGate

	// Gate: no-critical — fail if any critical findings.
	critCount := counts["critical"]
	gates = append(gates, PRGate{
		Name:   "no-critical",
		Passed: critCount == 0,
		Count:  critCount,
	})

	// Gate: no-new-warnings — placeholder for diff mode (always passes in full-scan mode).
	gates = append(gates, PRGate{
		Name:   "no-new-warnings",
		Passed: true,
		Count:  0,
	})

	// Gate: health-above-threshold — pass if score >= threshold.
	gates = append(gates, PRGate{
		Name:   "health-above-threshold",
		Passed: report.HealthScore.Score >= healthThreshold,
		Count:  healthThreshold,
	})

	// Determine overall conclusion.
	conclusion := "success"
	for _, g := range gates {
		if !g.Passed {
			conclusion = "failure"
			break
		}
	}
	if conclusion == "success" && counts["warning"] > 0 {
		conclusion = "neutral"
	}

	decision := PRDecision{
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

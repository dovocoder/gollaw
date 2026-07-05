package reporter

import (
	"encoding/json"
	"fmt"
)

// ImpactReport is a per-category and per-severity issue count report for tracking over time.
//gollaw:keep
type ImpactReport struct {
	TotalIssues      int            `json:"total_issues"`
	ByCategory       map[string]int `json:"by_category"`
	BySeverity       map[string]int `json:"by_severity"`
	HealthScore      int            `json:"health_score"`
	FilesAffected    int            `json:"files_affected"`
	FunctionsAnalyzed int           `json:"functions_analyzed"`
}

// FormatImpact renders an impact report as JSON with per-category and per-severity counts.
//gollaw:keep
func FormatImpact(report *Report) ([]byte, error) {
	byCategory := make(map[string]int)
	bySeverity := map[string]int{
		"critical": 0,
		"warning":  0,
		"info":     0,
		"hint":     0,
	}
	fileSet := make(map[string]struct{})

	for _, f := range report.Findings {
		byCategory[string(f.Category)]++
		bySeverity[string(f.Severity)]++
		fileSet[f.File] = struct{}{}
	}

	impact := ImpactReport{
		TotalIssues:       len(report.Findings),
		ByCategory:        byCategory,
		BySeverity:        bySeverity,
		HealthScore:       report.HealthScore.Score,
		FilesAffected:     len(fileSet),
		FunctionsAnalyzed: report.Stats.Functions,
	}

	out, err := json.MarshalIndent(impact, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal impact report: %w", err)
	}
	return out, nil
}

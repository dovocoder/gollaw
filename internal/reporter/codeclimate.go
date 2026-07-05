package reporter

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/dovocoder/gollaw/internal/analyzer"
)

// codeClimateIssue is a single issue in CodeClimate / GitLab Code Quality format.
type codeClimateIssue struct {
	Description string             `json:"description"`
	Fingerprint string             `json:"fingerprint"`
	Severity    string             `json:"severity"`
	Location    codeClimateLocation `json:"location"`
}

// codeClimateLocation describes where an issue was found.
type codeClimateLocation struct {
	Path  string              `json:"path"`
	Lines codeClimateLines     `json:"lines"`
}

// codeClimateLines holds line range info.
type codeClimateLines struct {
	Begin int `json:"begin"`
}

// formatCodeClimate renders the report as a CodeClimate / GitLab Code Quality JSON array.
func formatCodeClimate(report *Report) ([]byte, error) {
	issues := make([]codeClimateIssue, 0, len(report.Findings))
	for _, f := range report.Findings {
		issue := codeClimateIssue{
			Description: f.Message,
			Fingerprint: codeClimateFingerprint(f),
			Severity:    codeClimateSeverity(f.Severity),
			Location: codeClimateLocation{
				Path: f.File,
				Lines: codeClimateLines{
					Begin: f.Line,
				},
			},
		}
		issues = append(issues, issue)
	}

	out, err := json.MarshalIndent(issues, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal codeclimate issues: %w", err)
	}
	return out, nil
}

func codeClimateSeverity(sev analyzer.Severity) string {
	switch sev {
	case analyzer.SeverityCritical:
		return "blocker"
	case analyzer.SeverityWarning:
		return "major"
	case analyzer.SeverityInfo:
		return "minor"
	case analyzer.SeverityHint:
		return "info"
	default:
		return "info"
	}
}

func codeClimateFingerprint(f analyzer.Finding) string {
	raw := fmt.Sprintf("%s:%d:%s", f.File, f.Line, f.RuleID)
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

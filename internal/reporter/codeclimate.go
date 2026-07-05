package reporter

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/dovocoder/gollaw/internal/analyzer"
)

// CodeClimateIssue is a single issue in CodeClimate / GitLab Code Quality format.
//gollaw:keep
type CodeClimateIssue struct {
	Description string             `json:"description"`
	Fingerprint string             `json:"fingerprint"`
	Severity    string             `json:"severity"`
	Location    CodeClimateLocation `json:"location"`
}

// CodeClimateLocation describes where an issue was found.
//gollaw:keep
type CodeClimateLocation struct {
	Path  string              `json:"path"`
	Lines CodeClimateLines     `json:"lines"`
}

// CodeClimateLines holds line range info.
//gollaw:keep
type CodeClimateLines struct {
	Begin int `json:"begin"`
}

// FormatCodeClimate renders the report as a CodeClimate / GitLab Code Quality JSON array.
//gollaw:keep
func FormatCodeClimate(report *Report) ([]byte, error) {
	issues := make([]CodeClimateIssue, 0, len(report.Findings))
	for _, f := range report.Findings {
		issue := CodeClimateIssue{
			Description: f.Message,
			Fingerprint: codeClimateFingerprint(f),
			Severity:    codeClimateSeverity(f.Severity),
			Location: CodeClimateLocation{
				Path: f.File,
				Lines: CodeClimateLines{
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

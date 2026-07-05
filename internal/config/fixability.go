package config

import (
	"fmt"

	"github.com/dovocoder/gollaw/internal/analyzer"
)

// FixabilityInfo tracks whether a finding is auto-fixable.
type FixabilityInfo struct {
	Analyzer    string
	RuleID      string
	IsFixable   bool
	FixKind     string
	Confidence  string
	Description string
}

// GetFixability returns fixability info for an analyzer+ruleID combination.
func GetFixability(analyzerName, ruleID string) FixabilityInfo {
	switch {
	case analyzerName == "deadcode" && ruleID == "GLW-DC001":
		return FixabilityInfo{analyzerName, ruleID, true, "remove", "high", "Remove unreachable function"}
	case analyzerName == "unused-deps" && ruleID == "GLW-UD001":
		return FixabilityInfo{analyzerName, ruleID, true, "replace", "high", "Run go mod tidy"}
	case analyzerName == "naming" && ruleID == "GLW-NM001":
		return FixabilityInfo{analyzerName, ruleID, true, "rename", "medium", "Rename to Go convention"}
	case analyzerName == "unused-files" && ruleID == "GLW-UF001":
		return FixabilityInfo{analyzerName, ruleID, true, "remove", "medium", "Remove unused file"}
	case analyzerName == "thin-wrappers" && ruleID == "GLW-TW001":
		return FixabilityInfo{analyzerName, ruleID, true, "remove", "low", "Remove thin wrapper"}
	case analyzerName == "unused-overrides" && ruleID == "GLW-UO001":
		return FixabilityInfo{analyzerName, ruleID, true, "remove", "high", "Remove unused replace directive"}
	case analyzerName == "dead-flags" && ruleID == "GLW-DF001":
		return FixabilityInfo{analyzerName, ruleID, true, "remove", "medium", "Remove unused constant"}
	default:
		return FixabilityInfo{analyzerName, ruleID, false, "", "", ""}
	}
}

// IsFixable checks if a finding is auto-fixable.
func IsFixable(f analyzer.Finding) bool {
	return GetFixability(f.Analyzer, f.RuleID).IsFixable
}

// GetFixKind returns the fix kind for a finding.
func GetFixKind(f analyzer.Finding) string {
	return GetFixability(f.Analyzer, f.RuleID).FixKind
}

// ValidateFixability checks if a fixability entry is valid.
func ValidateFixability(info FixabilityInfo) error {
	if !info.IsFixable {
		return nil
	}
	validKinds := map[string]bool{"remove": true, "unexport": true, "rename": true, "replace": true, "import": true}
	if !validKinds[info.FixKind] {
		return fmt.Errorf("invalid fix kind: %s", info.FixKind)
	}
	return nil
}

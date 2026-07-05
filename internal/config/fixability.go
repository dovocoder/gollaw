package config

// fixabilityInfo tracks whether a finding is auto-fixable.
type fixabilityInfo struct {
	Analyzer    string
	RuleID      string
	FixKind     string
	Confidence  string
	Description string
}

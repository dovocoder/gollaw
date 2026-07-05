package baseline

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/dovocoder/gollaw/internal/analyzer"
)

const (
	baselineDir  = ".gollaw"
	baselineFile = "baseline.json"
)

// baselineData is the JSON representation of the baseline file.
type baselineData struct {
	Version  string             `json:"version"`
	Findings []analyzer.Finding `json:"findings"`
}

// findingKey is the tuple used to match findings across runs.
type findingKey struct {
	File     string
	Line     int
	RuleID   string
	Analyzer string
}

// keyOf extracts the matching key from a finding.
func keyOf(f analyzer.Finding) findingKey {
	return findingKey{
		File:     f.File,
		Line:     f.Line,
		RuleID:   f.RuleID,
		Analyzer: f.Analyzer,
	}
}

// buildSet creates a set of finding keys for O(1) lookup.
func buildSet(findings []analyzer.Finding) map[findingKey]bool {
	set := make(map[findingKey]bool, len(findings))
	for _, f := range findings {
		set[keyOf(f)] = true
	}
	return set
}

// Save writes the baseline snapshot to .gollaw/baseline.json under the given
// project root path. The directory is created if it doesn't exist.
func Save(projectRoot string, findings []analyzer.Finding) error {
	dir := filepath.Join(projectRoot, baselineDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create baseline directory: %w", err)
	}

	data := baselineData{
		Version:  "1",
		Findings: findings,
	}

	raw, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal baseline: %w", err)
	}

	path := filepath.Join(dir, baselineFile)
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		return fmt.Errorf("write baseline file: %w", err)
	}

	return nil
}

// Load reads the baseline snapshot from .gollaw/baseline.json under the given
// project root path. Returns nil findings (without error) if the file does
// not exist.
func Load(projectRoot string) ([]analyzer.Finding, error) {
	path := filepath.Join(projectRoot, baselineDir, baselineFile)

	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read baseline file: %w", err)
	}

	var data baselineData
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, fmt.Errorf("parse baseline file: %w", err)
	}

	return data.Findings, nil
}

// Diff returns only the findings in current that are NOT in baseline.
// Findings are matched by (File, Line, RuleID, Analyzer) tuple.
func Diff(baseline []analyzer.Finding, current []analyzer.Finding) []analyzer.Finding {
	baseSet := buildSet(baseline)
	var newFindings []analyzer.Finding
	for _, f := range current {
		if !baseSet[keyOf(f)] {
			newFindings = append(newFindings, f)
		}
	}
	return newFindings
}



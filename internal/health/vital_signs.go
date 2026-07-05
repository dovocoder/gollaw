// Package health provides project-wide health metrics, refactoring targets,
// trend tracking, threshold overrides, and analysis timing.
package health

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/dovocoder/gollaw/internal/analyzer"
	"github.com/dovocoder/gollaw/internal/filescore"
	"github.com/dovocoder/gollaw/internal/reporter"
)

// vitalSigns is a project-wide metrics snapshot.
type vitalSigns struct {
	// Counts
	TotalFiles    int `json:"totalFiles"`
	TotalPackages int `json:"totalPackages"`
	TotalFunctions int `json:"totalFunctions"`
	TotalTypes    int `json:"totalTypes"`
	TotalDecls    int `json:"totalDecls"`

	// Findings
	CriticalCount  int `json:"criticalCount"`
	WarningCount   int `json:"warningCount"`
	InfoCount      int `json:"infoCount"`
	HintCount      int `json:"hintCount"`
	TotalFindings  int `json:"totalFindings"`

	// Health
	HealthScore int    `json:"healthScore"`
	HealthGrade string `json:"healthGrade"`

	// Penalty per category (weighted)
	ByCategory map[string]int `json:"byCategory"`

	// Complexity
	AvgComplexity float64 `json:"avgComplexity"`
	MaxComplexity int      `json:"maxComplexity"`

	// Code quality metrics
	DuplicationCount int `json:"duplicationCount"`
	DeadCodeCount    int `json:"deadCodeCount"`
	UnusedCount      int `json:"unusedCount"`

	// Coverage
	CoveragePercent float64 `json:"coveragePercent"`

	// Fan-in / Fan-out averages
	FanInAvg  float64 `json:"fanInAvg"`
	FanOutAvg float64 `json:"fanOutAvg"`

	// Timestamp of this snapshot
	Timestamp string `json:"timestamp"`
}

// ComputeVitalSigns builds a project-wide metrics snapshot from findings,
// codebase stats, per-file scores, and coverage percentage.
func ComputeVitalSigns(
	findings []analyzer.Finding,
	stats reporter.CodebaseStats,
	fileScores []filescore.FileHealthScore,
	coveragePercent float64,
) *vitalSigns {
	vs := initVitalSigns(stats)
	weights := severityWeights()
	penalty := processFindings(vs, findings, weights)
	computeHealthScore(vs, penalty, stats.Functions)
	vs.CoveragePercent = coveragePercent
	return vs
}

// initVitalSigns creates the initial vitalSigns struct from codebase stats.
func initVitalSigns(stats reporter.CodebaseStats) *vitalSigns {
	return &vitalSigns{
		TotalFiles:     stats.Files,
		TotalPackages:  stats.Packages,
		TotalFunctions: stats.Functions,
		TotalTypes:     stats.Types,
		TotalDecls:     stats.Decls,
		ByCategory:     make(map[string]int),
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
	}
}

// severityWeights returns the penalty weight per severity level.
func severityWeights() map[analyzer.Severity]int {
	return map[analyzer.Severity]int{
		analyzer.SeverityCritical: 25,
		analyzer.SeverityWarning:  8,
		analyzer.SeverityInfo:     2,
		analyzer.SeverityHint:     1,
	}
}

// processFindings iterates findings, updating counts and returning total penalty.
func processFindings(vs *vitalSigns, findings []analyzer.Finding, weights map[analyzer.Severity]int) int {
	penalty := 0
	totalComplexity := 0
	complexitySamples := 0

	for _, f := range findings {
		vs.TotalFindings++
		updateSeverityCounts(vs, f.Severity)

		w := weights[f.Severity]
		penalty += w
		vs.ByCategory[string(f.Category)] += w

		updateCategoryCounts(vs, f, &totalComplexity, &complexitySamples)
	}

	if complexitySamples > 0 {
		vs.AvgComplexity = float64(totalComplexity) / float64(complexitySamples)
	}
	return penalty
}

// updateSeverityCounts increments the count for the given severity.
func updateSeverityCounts(vs *vitalSigns, severity analyzer.Severity) {
	switch severity {
	case analyzer.SeverityCritical:
		vs.CriticalCount++
	case analyzer.SeverityWarning:
		vs.WarningCount++
	case analyzer.SeverityInfo:
		vs.InfoCount++
	case analyzer.SeverityHint:
		vs.HintCount++
	}
}

// updateCategoryCounts updates category-based counts and complexity tracking.
func updateCategoryCounts(vs *vitalSigns, f analyzer.Finding, totalComplexity, complexitySamples *int) {
	switch f.Category {
	case analyzer.CategoryDeadCode:
		vs.DeadCodeCount++
	case analyzer.CategoryDuplication:
		vs.DuplicationCount++
	case analyzer.CategoryUnused:
		vs.UnusedCount++
	case analyzer.CategoryComplexity:
		c := extractComplexity(f)
		if c > 0 {
			*totalComplexity += c
			*complexitySamples++
			if c > vs.MaxComplexity {
				vs.MaxComplexity = c
			}
		}
	}
}

// computeHealthScore normalizes penalty and sets the health score and grade.
func computeHealthScore(vs *vitalSigns, penalty, functionCount int) {
	if functionCount == 0 {
		functionCount = 1
	}
	findingsPer100 := float64(penalty) * 100.0 / float64(functionCount)
	scaledPenalty := int(math.Sqrt(findingsPer100) * 10)

	score := 100 - scaledPenalty
	if score < 0 {
		score = 0
	}
	vs.HealthScore = score
	vs.HealthGrade = gradeFor(score)
}

// extractComplexity tries to parse a complexity number from a finding's detail
// or message. Returns 0 if no number is found.
func extractComplexity(f analyzer.Finding) int {
	// Look for patterns like "complexity 42" or "cc=42" in the detail/message
	for _, text := range []string{f.Detail, f.Message} {
		if c := parseTrailingNumber(text); c > 0 {
			return c
		}
	}
	return 0
}

// parseTrailingNumber extracts the last integer found in a string.
func parseTrailingNumber(s string) int {
	if s == "" {
		return 0
	}
	var nums []int
	var current int
	inNum := false
	for _, ch := range s {
		if ch >= '0' && ch <= '9' {
			current = current*10 + int(ch-'0')
			inNum = true
		} else {
			if inNum {
				nums = append(nums, current)
				current = 0
				inNum = false
			}
		}
	}
	if inNum {
		nums = append(nums, current)
	}
	if len(nums) == 0 {
		return 0
	}
	return nums[len(nums)-1]
}

func gradeFor(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 60:
		return "D"
	case score >= 50:
		return "E"
	default:
		return "F"
	}
}

// FormatVitalSignsText formats vital signs as a human-readable text report.
func FormatVitalSignsText(vs *vitalSigns) string {
	var b strings.Builder

	b.WriteString("─── Vital Signs ───\n\n")
	formatCodebaseSection(&b, vs)
	formatFindingsSection(&b, vs)
	formatHealthSection(&b, vs)
	formatComplexitySection(&b, vs)
	formatCodeQualitySection(&b, vs)
	formatCoverageSection(&b, vs)
	formatDependenciesSection(&b, vs)
	fmt.Fprintf(&b, "\nTimestamp: %s\n", vs.Timestamp)

	return b.String()
}

// metricEntry pairs a display label with an integer value for metric sections.
type metricEntry struct {
	label string
	value int
}

// formatCodebaseSection writes the codebase counts section.
func formatCodebaseSection(b *strings.Builder, vs *vitalSigns) {
	writeMetricSection(b, "Codebase:\n", []metricEntry{
		{"Files:", vs.TotalFiles},
		{"Packages:", vs.TotalPackages},
		{"Functions:", vs.TotalFunctions},
		{"Types:", vs.TotalTypes},
		{"Decls:", vs.TotalDecls},
	})
}

// formatFindingsSection writes the findings counts section.
func formatFindingsSection(b *strings.Builder, vs *vitalSigns) {
	writeMetricSection(b, "\nFindings:\n", []metricEntry{
		{"Total:", vs.TotalFindings},
		{"Critical:", vs.CriticalCount},
		{"Warning:", vs.WarningCount},
		{"Info:", vs.InfoCount},
		{"Hint:", vs.HintCount},
	})
}

// writeMetricSection writes a header followed by labelled metric lines.
func writeMetricSection(b *strings.Builder, header string, entries []metricEntry) {
	b.WriteString(header)
	for _, e := range entries {
		fmt.Fprintf(b, "  %-11s%d\n", e.label, e.value)
	}
}

// formatHealthSection writes the health score and penalty-by-category section.
func formatHealthSection(b *strings.Builder, vs *vitalSigns) {
	b.WriteString("\nHealth:\n")
	fmt.Fprintf(b, "  Score: %d/100 (grade: %s)\n", vs.HealthScore, vs.HealthGrade)

	if len(vs.ByCategory) > 0 {
		b.WriteString("  Penalty by category:\n")
		cats := make([]string, 0, len(vs.ByCategory))
		for c := range vs.ByCategory {
			cats = append(cats, c)
		}
		sort.Strings(cats)
		for _, c := range cats {
			fmt.Fprintf(b, "    %s: -%d\n", c, vs.ByCategory[c])
		}
	}
}

// formatComplexitySection writes the complexity metrics section.
func formatComplexitySection(b *strings.Builder, vs *vitalSigns) {
	b.WriteString("\nComplexity:\n")
	fmt.Fprintf(b, "  Average: %.1f\n", vs.AvgComplexity)
	fmt.Fprintf(b, "  Max:     %d\n", vs.MaxComplexity)
}

// formatCodeQualitySection writes the code quality metrics section.
func formatCodeQualitySection(b *strings.Builder, vs *vitalSigns) {
	b.WriteString("\nCode Quality:\n")
	fmt.Fprintf(b, "  Duplication: %d\n", vs.DuplicationCount)
	fmt.Fprintf(b, "  Dead code:   %d\n", vs.DeadCodeCount)
	fmt.Fprintf(b, "  Unused:      %d\n", vs.UnusedCount)
}

// formatCoverageSection writes the coverage section.
func formatCoverageSection(b *strings.Builder, vs *vitalSigns) {
	b.WriteString("\nCoverage:\n")
	fmt.Fprintf(b, "  %.1f%%\n", vs.CoveragePercent)
}

// formatDependenciesSection writes the fan-in/fan-out section if applicable.
func formatDependenciesSection(b *strings.Builder, vs *vitalSigns) {
	if vs.FanInAvg > 0 || vs.FanOutAvg > 0 {
		b.WriteString("\nDependencies:\n")
		fmt.Fprintf(b, "  Avg Fan-in:  %.1f\n", vs.FanInAvg)
		fmt.Fprintf(b, "  Avg Fan-out: %.1f\n", vs.FanOutAvg)
	}
}

// FormatVitalSignsJSON formats vital signs as indented JSON.
//gollaw:ignore thin-wrappers
func FormatVitalSignsJSON(vs *vitalSigns) ([]byte, error) {
	return json.MarshalIndent(vs, "", "  ")
}

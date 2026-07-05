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

// VitalSigns is a project-wide metrics snapshot.
type VitalSigns struct {
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
) *VitalSigns {
	vs := &VitalSigns{
		TotalFiles:     stats.Files,
		TotalPackages:  stats.Packages,
		TotalFunctions: stats.Functions,
		TotalTypes:     stats.Types,
		TotalDecls:     stats.Decls,
		ByCategory:     make(map[string]int),
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
	}

	weights := map[analyzer.Severity]int{
		analyzer.SeverityCritical: 25,
		analyzer.SeverityWarning:  8,
		analyzer.SeverityInfo:     2,
		analyzer.SeverityHint:     1,
	}

	penalty := 0
	totalComplexity := 0
	complexitySamples := 0

	for _, f := range findings {
		vs.TotalFindings++
		switch f.Severity {
		case analyzer.SeverityCritical:
			vs.CriticalCount++
		case analyzer.SeverityWarning:
			vs.WarningCount++
		case analyzer.SeverityInfo:
			vs.InfoCount++
		case analyzer.SeverityHint:
			vs.HintCount++
		}

		w := weights[f.Severity]
		penalty += w
		vs.ByCategory[string(f.Category)] += w

		switch f.Category {
		case analyzer.CategoryDeadCode:
			vs.DeadCodeCount++
		case analyzer.CategoryDuplication:
			vs.DuplicationCount++
		case analyzer.CategoryUnused:
			vs.UnusedCount++
		case analyzer.CategoryComplexity:
			// Try to extract complexity value from finding detail or message
			c := extractComplexity(f)
			if c > 0 {
				totalComplexity += c
				complexitySamples++
				if c > vs.MaxComplexity {
					vs.MaxComplexity = c
				}
			}
		}
	}

	// Normalize penalty relative to codebase size and apply diminishing returns.
	// A fixed penalty of 2 per info finding destroys the score for large codebases
	// with many minor findings. Instead, we scale by function count and use a
	// square-root curve so the marginal penalty decreases as findings accumulate.
	functionCount := stats.Functions
	if functionCount == 0 {
		functionCount = 1
	}
	// Scale factor: findings per 100 functions (so small codebases aren't over-penalized).
	findingsPer100 := float64(penalty) * 100.0 / float64(functionCount)
	// Diminishing returns: sqrt scaling.
	scaledPenalty := int(math.Sqrt(findingsPer100) * 10)

	score := 100 - scaledPenalty
	if score < 0 {
		score = 0
	}
	vs.HealthScore = score
	vs.HealthGrade = gradeFor(score)

	if complexitySamples > 0 {
		vs.AvgComplexity = float64(totalComplexity) / float64(complexitySamples)
	}

	vs.CoveragePercent = coveragePercent

	// Fan-in / Fan-out would come from dependency analysis; we approximate
	// from file scores if available (not directly available, so leave as 0
	// unless the caller provides additional data).
	vs.FanInAvg = 0
	vs.FanOutAvg = 0

	return vs
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
func FormatVitalSignsText(vs *VitalSigns) string {
	var b strings.Builder

	b.WriteString("─── Vital Signs ───\n\n")

	b.WriteString("Codebase:\n")
	fmt.Fprintf(&b, "  Files:     %d\n", vs.TotalFiles)
	fmt.Fprintf(&b, "  Packages:  %d\n", vs.TotalPackages)
	fmt.Fprintf(&b, "  Functions: %d\n", vs.TotalFunctions)
	fmt.Fprintf(&b, "  Types:     %d\n", vs.TotalTypes)
	fmt.Fprintf(&b, "  Decls:     %d\n", vs.TotalDecls)

	b.WriteString("\nFindings:\n")
	fmt.Fprintf(&b, "  Total:     %d\n", vs.TotalFindings)
	fmt.Fprintf(&b, "  Critical:  %d\n", vs.CriticalCount)
	fmt.Fprintf(&b, "  Warning:   %d\n", vs.WarningCount)
	fmt.Fprintf(&b, "  Info:      %d\n", vs.InfoCount)
	fmt.Fprintf(&b, "  Hint:      %d\n", vs.HintCount)

	b.WriteString("\nHealth:\n")
	fmt.Fprintf(&b, "  Score: %d/100 (grade: %s)\n", vs.HealthScore, vs.HealthGrade)

	if len(vs.ByCategory) > 0 {
		b.WriteString("  Penalty by category:\n")
		cats := make([]string, 0, len(vs.ByCategory))
		for c := range vs.ByCategory {
			cats = append(cats, c)
		}
		sort.Strings(cats)
		for _, c := range cats {
			fmt.Fprintf(&b, "    %s: -%d\n", c, vs.ByCategory[c])
		}
	}

	b.WriteString("\nComplexity:\n")
	fmt.Fprintf(&b, "  Average: %.1f\n", vs.AvgComplexity)
	fmt.Fprintf(&b, "  Max:     %d\n", vs.MaxComplexity)

	b.WriteString("\nCode Quality:\n")
	fmt.Fprintf(&b, "  Duplication: %d\n", vs.DuplicationCount)
	fmt.Fprintf(&b, "  Dead code:   %d\n", vs.DeadCodeCount)
	fmt.Fprintf(&b, "  Unused:      %d\n", vs.UnusedCount)

	b.WriteString("\nCoverage:\n")
	fmt.Fprintf(&b, "  %.1f%%\n", vs.CoveragePercent)

	if vs.FanInAvg > 0 || vs.FanOutAvg > 0 {
		b.WriteString("\nDependencies:\n")
		fmt.Fprintf(&b, "  Avg Fan-in:  %.1f\n", vs.FanInAvg)
		fmt.Fprintf(&b, "  Avg Fan-out: %.1f\n", vs.FanOutAvg)
	}

	fmt.Fprintf(&b, "\nTimestamp: %s\n", vs.Timestamp)

	return b.String()
}

// FormatVitalSignsJSON formats vital signs as indented JSON.
func FormatVitalSignsJSON(vs *VitalSigns) ([]byte, error) {
	return json.MarshalIndent(vs, "", "  ")
}

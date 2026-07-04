// Package xref provides cross-reference analysis: combining findings from
// multiple analyzers for higher-signal results.
package xref

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/dovocoder/gollaw/internal/analyzer"
)

// CombinedFinding represents overlapping findings from multiple analyzers.
type CombinedFinding struct {
	Findings   []analyzer.Finding `json:"findings"`
	Kind       string             `json:"kind"`
	File       string             `json:"file"`
	Line       int                `json:"line"`
	Message    string             `json:"message"`
	Suggestion string             `json:"suggestion"`
}

// CrossReference finds overlapping findings from different analyzers.
func CrossReference(findings []analyzer.Finding) []CombinedFinding {
	var combined []CombinedFinding

	// Group by file.
	byFile := make(map[string][]analyzer.Finding)
	for _, f := range findings {
		byFile[f.File] = append(byFile[f.File], f)
	}

	for file, fileFindings := range byFile {
		// duplicate-and-dead
		combined = append(combined, findOverlap(file, fileFindings, "duplication", "deadcode", "duplicate-and-dead",
			"This duplicated code is also dead — removing it will eliminate both issues.")...)

		// duplicate-and-unused
		combined = append(combined, findOverlap(file, fileFindings, "duplication", "unused", "duplicate-and-unused",
			"This duplicated code is also unused — removing it will eliminate both issues.")...)

		// complex-and-large
		combined = append(combined, findOverlap(file, fileFindings, "complexity", "large-functions", "complex-and-large",
			"This function is both complex and large — prioritize refactoring it.")...)

		// security-and-dead
		combined = append(combined, findOverlap(file, fileFindings, "security", "deadcode", "security-and-dead",
			"This security issue is in dead code — removing the dead code eliminates the vulnerability.")...)
	}

	sort.Slice(combined, func(i, j int) bool {
		if combined[i].File != combined[j].File {
			return combined[i].File < combined[j].File
		}
		return combined[i].Line < combined[j].Line
	})

	return combined
}

func findOverlap(file string, findings []analyzer.Finding, analyzer1, analyzer2, kind, suggestion string) []CombinedFinding {
	var result []CombinedFinding
	var set1, set2 []analyzer.Finding

	for _, f := range findings {
		if f.Analyzer == analyzer1 {
			set1 = append(set1, f)
		}
		if f.Analyzer == analyzer2 {
			set2 = append(set2, f)
		}
	}

	for _, f1 := range set1 {
		for _, f2 := range set2 {
			if rangesOverlap(f1, f2) {
				result = append(result, CombinedFinding{
					Findings:   []analyzer.Finding{f1, f2},
					Kind:       kind,
					File:       file,
					Line:       f1.Line,
					Message:    fmt.Sprintf("%s + %s overlap at %s:%d", analyzer1, analyzer2, file, f1.Line),
					Suggestion: suggestion,
				})
			}
		}
	}
	return result
}

func rangesOverlap(a, b analyzer.Finding) bool {
	aEnd := a.EndLine
	if aEnd == 0 {
		aEnd = a.Line
	}
	bEnd := b.EndLine
	if bEnd == 0 {
		bEnd = b.Line
	}
	return a.Line <= bEnd && aEnd >= b.Line
}

// FormatXRefText formats cross-reference findings as text.
func FormatXRefText(combined []CombinedFinding) string {
	if len(combined) == 0 {
		return "No cross-referenced findings.\n"
	}
	var b strings.Builder
	b.WriteString("─── Cross-Reference Analysis ───\n\n")
	for _, c := range combined {
		fmt.Fprintf(&b, "🔗 %s: %s\n", c.Kind, c.Message)
		fmt.Fprintf(&b, "   %s:%d\n", c.File, c.Line)
		for _, f := range c.Findings {
			fmt.Fprintf(&b, "   • %s: %s\n", f.Analyzer, f.Message)
		}
		if c.Suggestion != "" {
			fmt.Fprintf(&b, "   → %s\n", c.Suggestion)
		}
		b.WriteString("\n")
	}
	return b.String()
}

// FormatXRefJSON formats cross-reference findings as JSON.
func FormatXRefJSON(combined []CombinedFinding) ([]byte, error) {
	return json.MarshalIndent(combined, "", "  ")
}

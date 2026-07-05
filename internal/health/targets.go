package health

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/dovocoder/gollaw/internal/analyzer"
	"github.com/dovocoder/gollaw/internal/filescore"
)

// RefactoringTarget is a recommendation for a file or function that needs attention.
type RefactoringTarget struct {
	File          string          `json:"file"`
	Function      string          `json:"function,omitempty"`
	Score         int             `json:"score"`
	Category      string          `json:"category"`
	Effort        string          `json:"effort"`        // S, M, L, XL
	Confidence    string          `json:"confidence"`    // high, medium, low
	Evidence      []TargetEvidence `json:"evidence"`
	Recommendation string         `json:"recommendation"`
}

// TargetEvidence is a single piece of evidence supporting a refactoring target.
type TargetEvidence struct {
	Kind        string `json:"kind"`
	Description string `json:"description"`
}

// ComputeRefactoringTargets identifies the worst files and produces
// actionable refactoring recommendations.
func ComputeRefactoringTargets(
	findings []analyzer.Finding,
	fileScores []filescore.FileHealthScore,
) []RefactoringTarget {
	if len(fileScores) == 0 {
		return nil
	}

	// fileScores is already sorted by score ascending (worst first) from ScoreFiles,
	// but we sort again to be safe.
	sorted := make([]filescore.FileHealthScore, len(fileScores))
	copy(sorted, fileScores)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Score < sorted[j].Score
	})

	// Index findings by file
	findingsByFile := make(map[string][]analyzer.Finding)
	for _, f := range findings {
		findingsByFile[f.File] = append(findingsByFile[f.File], f)
	}

	maxTargets := 20
	if len(sorted) < maxTargets {
		maxTargets = len(sorted)
	}

	var targets []RefactoringTarget
	for i := 0; i < maxTargets; i++ {
		fs := sorted[i]
		fileFindings := findingsByFile[fs.File]
		if len(fileFindings) == 0 {
			// File has a score but no findings — skip if score is acceptable
			if fs.Score >= 80 {
				continue
			}
		}

		target := buildTarget(fs, fileFindings)
		targets = append(targets, target)
	}

	return targets
}

// buildTarget creates a RefactoringTarget from a file score and its findings.
func buildTarget(fs filescore.FileHealthScore, findings []analyzer.Finding) RefactoringTarget {
	dominantCategory := findDominantCategory(findings)
	criticalCount, warningCount := countBySeverity(findings)
	deadCount, dupCount, complexityVal, complexityFunc := categorizeFindings(findings)

	effort := effortForCategory(dominantCategory)
	confidence := confidenceFor(criticalCount, warningCount, len(findings))
	evidence := buildEvidence(fs, findings, criticalCount, deadCount, dupCount, complexityVal, complexityFunc)
	recommendation := buildRecommendation(dominantCategory, deadCount, complexityFunc, complexityVal, dupCount, findings)

	return RefactoringTarget{
		File:           fs.File,
		Function:       complexityFunc,
		Score:          fs.Score,
		Category:       dominantCategory,
		Effort:         effort,
		Confidence:     confidence,
		Evidence:       evidence,
		Recommendation: recommendation,
	}
}

// findDominantCategory returns the category with the highest weighted penalty.
func findDominantCategory(findings []analyzer.Finding) string {
	if len(findings) == 0 {
		return string(analyzer.CategoryCodeSmell)
	}

	weights := map[analyzer.Severity]int{
		analyzer.SeverityCritical: 25,
		analyzer.SeverityWarning:  8,
		analyzer.SeverityInfo:     2,
		analyzer.SeverityHint:     1,
	}

	byCat := make(map[string]int)
	for _, f := range findings {
		byCat[string(f.Category)] += weights[f.Severity]
	}

	bestCat := ""
	bestWeight := -1
	for cat, w := range byCat {
		if w > bestWeight {
			bestWeight = w
			bestCat = cat
		}
	}
	return bestCat
}

func countBySeverity(findings []analyzer.Finding) (critical, warning int) {
	for _, f := range findings {
		switch f.Severity {
		case analyzer.SeverityCritical:
			critical++
		case analyzer.SeverityWarning:
			warning++
		}
	}
	return
}

// categorizeFindings extracts counts and complexity info from findings.
func categorizeFindings(findings []analyzer.Finding) (deadCount, dupCount, maxComplexity int, complexityFunc string) {
	for _, f := range findings {
		switch f.Category {
		case analyzer.CategoryDeadCode:
			deadCount++
		case analyzer.CategoryDuplication:
			dupCount++
		case analyzer.CategoryComplexity:
			c := extractComplexity(f)
			if c > maxComplexity {
				maxComplexity = c
				complexityFunc = extractFunctionName(f)
			}
		}
	}
	return
}

// extractFunctionName tries to get a function name from a finding's message or detail.
func extractFunctionName(f analyzer.Finding) string {
	// Try message first — often "function X has complexity Y"
	for _, text := range []string{f.Message, f.Detail} {
		if name := extractBetween(text, "function ", " "); name != "" {
			return name
		}
		if name := extractBetween(text, "func ", " "); name != "" {
			return name
		}
	}
	// Fall back to the rule ID or analyzer
	if f.RuleID != "" {
		return f.RuleID
	}
	return ""
}

// extractBetween extracts the substring between two delimiters.
func extractBetween(s, start, end string) string {
	idx := strings.Index(s, start)
	if idx < 0 {
		return ""
	}
	s = s[idx+len(start):]
	idx = strings.Index(s, end)
	if idx < 0 {
		return s
	}
	return s[:idx]
}

func effortForCategory(cat string) string {
	switch cat {
	case string(analyzer.CategoryDeadCode):
		return "S"
	case string(analyzer.CategoryDuplication):
		return "M"
	case string(analyzer.CategoryComplexity):
		return "L"
	case "security":
		return "XL"
	default:
		return "M"
	}
}

func confidenceFor(criticalCount, warningCount, total int) string {
	if criticalCount > 0 {
		return "high"
	}
	if warningCount >= 3 {
		return "high"
	}
	if warningCount > 0 || total >= 5 {
		return "medium"
	}
	return "low"
}

func buildEvidence(
	fs filescore.FileHealthScore,
	findings []analyzer.Finding,
	criticalCount, deadCount, dupCount, complexityVal int,
	complexityFunc string,
) []TargetEvidence {
	var evidence []TargetEvidence

	if criticalCount > 0 {
		evidence = append(evidence, TargetEvidence{
			Kind:        "critical",
			Description: fmt.Sprintf("file has %d critical findings", criticalCount),
		})
	}

	if complexityVal > 0 && complexityFunc != "" {
		evidence = append(evidence, TargetEvidence{
			Kind:        "complexity",
			Description: fmt.Sprintf("function %s has complexity %d", complexityFunc, complexityVal),
		})
	}

	if dupCount > 0 {
		evidence = append(evidence, TargetEvidence{
			Kind:        "duplication",
			Description: fmt.Sprintf("%d duplicated blocks", dupCount),
		})
	}

	if deadCount > 0 {
		evidence = append(evidence, TargetEvidence{
			Kind:        "dead-code",
			Description: fmt.Sprintf("%d dead code findings", deadCount),
		})
	}

	// Add finding count evidence
	evidence = append(evidence, TargetEvidence{
		Kind:        "score",
		Description: fmt.Sprintf("file health score is %d/100 with %d total findings", fs.Score, len(findings)),
	})

	return evidence
}

func buildRecommendation(
	dominantCategory string,
	deadCount int,
	complexityFunc string,
	complexityVal int,
	dupCount int,
	findings []analyzer.Finding,
) string {
	switch dominantCategory {
	case string(analyzer.CategoryDeadCode):
		return fmt.Sprintf("Remove %d dead functions", deadCount)
	case string(analyzer.CategoryComplexity):
		if complexityFunc != "" && complexityVal > 0 {
			return fmt.Sprintf("Refactor function %s (complexity %d)", complexityFunc, complexityVal)
		}
		return "Reduce function complexity"
	case string(analyzer.CategoryDuplication):
		// Find first duplication finding with a line number
		for _, f := range findings {
			if f.Category == analyzer.CategoryDuplication && f.Line > 0 {
				return fmt.Sprintf("Extract duplicated block at line %d", f.Line)
			}
		}
		return fmt.Sprintf("Extract %d duplicated blocks", dupCount)
	case "security":
		return "Review and fix security findings"
	default:
		return fmt.Sprintf("Address %d findings in this file", len(findings))
	}
}

// FormatTargetsText formats refactoring targets as a human-readable text report.
func FormatTargetsText(targets []RefactoringTarget) string {
	if len(targets) == 0 {
		return "No refactoring targets identified.\n"
	}

	var b strings.Builder
	b.WriteString("─── Refactoring Targets ───\n\n")

	for i, t := range targets {
		fmt.Fprintf(&b, "%d. %s\n", i+1, t.File)
		if t.Function != "" {
			fmt.Fprintf(&b, "   Function: %s\n", t.Function)
		}
		fmt.Fprintf(&b, "   Score: %d  Category: %s  Effort: %s  Confidence: %s\n",
			t.Score, t.Category, t.Effort, t.Confidence)
		for _, e := range t.Evidence {
			fmt.Fprintf(&b, "   • [%s] %s\n", e.Kind, e.Description)
		}
		fmt.Fprintf(&b, "   → %s\n\n", t.Recommendation)
	}

	return b.String()
}

// FormatTargetsJSON formats refactoring targets as indented JSON.
func FormatTargetsJSON(targets []RefactoringTarget) ([]byte, error) {
	return json.MarshalIndent(targets, "", "  ")
}

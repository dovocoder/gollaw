// Package filescore computes per-file health scores.
package filescore

import (
	"fmt"
	"sort"
	"strings"

	"github.com/dovocoder/gollaw/internal/analyzer"
)

// fileStats holds per-file statistics.
type fileStats struct {
	LineCount  int
	FuncCount  int
	Complexity int
}

// fileStatsMap maps file paths to their stats.
type fileStatsMap map[string]fileStats

// FileHealthScore is the health score for a single file.
type FileHealthScore struct {
	File         string         `json:"file"`
	Score        int            `json:"score"`
	Grade        string         `json:"grade"`
	FindingCount int            `json:"findingCount"`
	BySeverity   map[string]int `json:"bySeverity"`
	ByCategory   map[string]int `json:"byCategory"`
	LineCount    int            `json:"lineCount"`
	FuncCount    int            `json:"funcCount"`
}

// severityWeights returns the per-severity penalty weights.
func severityWeights() map[analyzer.Severity]int {
	return map[analyzer.Severity]int{
		analyzer.SeverityCritical: 25,
		analyzer.SeverityWarning:  8,
		analyzer.SeverityInfo:     2,
		analyzer.SeverityHint:     1,
	}
}

// ScoreFiles computes per-file health scores from findings.
func ScoreFiles(findings []analyzer.Finding, stats fileStatsMap) []FileHealthScore {
	weights := severityWeights()
	fileMap := make(map[string]*FileHealthScore)

	for _, f := range findings {
		score := getOrCreateScore(fileMap, f.File, stats)
		score.FindingCount++
		score.BySeverity[string(f.Severity)]++
		score.ByCategory[string(f.Category)] += weights[f.Severity]
	}

	scores := finalizeScores(fileMap, weights)
	sort.Slice(scores, func(i, j int) bool {
		return scores[i].Score < scores[j].Score
	})
	return scores
}

// getOrCreateScore returns the existing score for a file or creates a new one.
func getOrCreateScore(fileMap map[string]*FileHealthScore, file string, stats fileStatsMap) *FileHealthScore {
	if s, ok := fileMap[file]; ok {
		return s
	}
	score := &FileHealthScore{
		File:       file,
		BySeverity: make(map[string]int),
		ByCategory: make(map[string]int),
	}
	if stats != nil {
		if s, ok := stats[file]; ok {
			score.LineCount = s.LineCount
			score.FuncCount = s.FuncCount
		}
	}
	fileMap[file] = score
	return score
}

// finalizeScores converts the score map to a slice, computing penalty and grade.
func finalizeScores(fileMap map[string]*FileHealthScore, weights map[analyzer.Severity]int) []FileHealthScore {
	var scores []FileHealthScore
	for _, s := range fileMap {
		penalty := 0
		for _, p := range s.ByCategory {
			penalty += p
		}
		s.Score = 100 - penalty
		if s.Score < 0 {
			s.Score = 0
		}
		s.Grade = gradeFor(s.Score)
		scores = append(scores, *s)
	}
	return scores
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

// FormatFileScoresText formats file scores as a text table.
func FormatFileScoresText(scores []FileHealthScore) string {
	if len(scores) == 0 {
		return "No findings to score.\n"
	}
	var b strings.Builder
	b.WriteString("─── Per-File Health Scores ───\n\n")
	fmt.Fprintf(&b, "%-60s %5s %5s %5s\n", "FILE", "SCORE", "GRADE", "FINDS")
	b.WriteString(strings.Repeat("─", 80) + "\n")
	for _, s := range scores {
		fmt.Fprintf(&b, "%-60s %4d  %s     %4d\n", shortPath(s.File), s.Score, s.Grade, s.FindingCount)
	}
	return b.String()
}

func shortPath(path string) string {
	parts := strings.Split(path, "/")
	if len(parts) <= 3 {
		return path
	}
	return strings.Join(parts[len(parts)-3:], "/")
}

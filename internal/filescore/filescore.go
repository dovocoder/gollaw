// Package filescore computes per-file health scores.
package filescore

import (
	"fmt"
	"sort"
	"strings"

	"github.com/dovocoder/gollaw/internal/analyzer"
)

// FileStats holds per-file statistics.
type FileStats struct {
	LineCount  int
	FuncCount  int
	Complexity int
}

// FileStatsMap maps file paths to their stats.
type FileStatsMap map[string]FileStats

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

// ScoreFiles computes per-file health scores from findings.
func ScoreFiles(findings []analyzer.Finding, stats FileStatsMap) []FileHealthScore {
	weights := map[analyzer.Severity]int{
		analyzer.SeverityCritical: 25,
		analyzer.SeverityWarning:  8,
		analyzer.SeverityInfo:     2,
		analyzer.SeverityHint:     1,
	}

	fileMap := make(map[string]*FileHealthScore)

	for _, f := range findings {
		score, ok := fileMap[f.File]
		if !ok {
			score = &FileHealthScore{
				File:       f.File,
				BySeverity: make(map[string]int),
				ByCategory: make(map[string]int),
			}
			if stats != nil {
				if s, ok := stats[f.File]; ok {
					score.LineCount = s.LineCount
					score.FuncCount = s.FuncCount
				}
			}
			fileMap[f.File] = score
		}
		score.FindingCount++
		score.BySeverity[string(f.Severity)]++
		score.ByCategory[string(f.Category)] += weights[f.Severity]
	}

	var scores []FileHealthScore
	for _, s := range fileMap {
		penalty := 0
		for _, w := range weights {
			penalty += s.BySeverity[string(severityFromWeight(w, weights))] * w
		}
		// Recalculate penalty from byCategory
		penalty = 0
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

	sort.Slice(scores, func(i, j int) bool {
		return scores[i].Score < scores[j].Score
	})

	return scores
}

func severityFromWeight(w int, weights map[analyzer.Severity]int) analyzer.Severity {
	for sev, weight := range weights {
		if weight == w {
			return sev
		}
	}
	return analyzer.SeverityInfo
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

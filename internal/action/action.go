// Package action implements the GitHub Action integration for Gollaw.
// It runs analysis on changed files and formats the output as a GitHub PR comment.
package action

import (
	"fmt"
	"strings"

	"github.com/dovocoder/gollaw/internal/analyzer"
	"github.com/dovocoder/gollaw/internal/reporter"
)

// actionVersion is set at build time via -ldflags to avoid an import cycle with internal/cli.
var actionVersion = "0.3.0-dev"

// FormatPRComment formats an audit report as a GitHub PR comment in markdown.
// The auditReport should be a *reporter.Report.
func FormatPRComment(auditReport interface{}) string {
	rep, ok := auditReport.(*reporter.Report)
	if !ok {
		return "## Gollaw\n\nError: invalid report type"
	}

	var b strings.Builder
	writePRCommentHeader(&b, rep)
	writePRCommentSummary(&b, rep)

	if rep.Summary.Total == 0 {
		fmt.Fprintf(&b, "### ✅ No issues found\n\n")
		fmt.Fprintf(&b, "Gollaw found no issues in the analyzed codebase. Great job!\n")
		return b.String()
	}

	writePRCommentFindings(&b, rep)
	writePRCommentScoreBreakdown(&b, rep)
	return b.String()
}

func writePRCommentHeader(b *strings.Builder, rep *reporter.Report) {
	fmt.Fprintf(b, "## 🗡️ Gollaw Analysis\n\n")
	fmt.Fprintf(b, "Health Score: **%d/100** (Grade: **%s**)\n\n", rep.HealthScore.Score, rep.HealthScore.Grade)
}

func writePRCommentSummary(b *strings.Builder, rep *reporter.Report) {
	fmt.Fprintf(b, "### Summary\n\n")
	fmt.Fprintf(b, "- **Total findings:** %d\n", rep.Summary.Total)
	if rep.Summary.Total > 0 {
		writeSeverityBreakdown(b, rep)
	}
	fmt.Fprintf(b, "- **Codebase:** %d packages, %d files, %d functions\n\n", rep.Stats.Packages, rep.Stats.Files, rep.Stats.Functions)
}

func writeSeverityBreakdown(b *strings.Builder, rep *reporter.Report) {
	fmt.Fprintf(b, "- **By severity:** ")
	parts := make([]string, 0)
	for _, sev := range []string{"critical", "warning", "info", "hint"} {
		if count, ok := rep.Summary.BySeverity[sev]; ok && count > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", count, sev))
		}
	}
	b.WriteString(strings.Join(parts, ", "))
	b.WriteString("\n")
}

func writePRCommentFindings(b *strings.Builder, rep *reporter.Report) {
	fmt.Fprintf(b, "### Findings\n\n")
	fmt.Fprintf(b, "| Severity | File | Line | Rule | Message |\n")
	fmt.Fprintf(b, "|----------|------|------|------|--------|\n")
	for _, f := range rep.Findings {
		file := shortPath(f.File)
		sev := severityEmoji(f.Severity)
		msg := strings.ReplaceAll(f.Message, "|", "\\|")
		fmt.Fprintf(b, "| %s | `%s` | %d | %s | %s |\n", sev, file, f.Line, f.RuleID, msg)
	}
}

func writePRCommentScoreBreakdown(b *strings.Builder, rep *reporter.Report) {
	if len(rep.HealthScore.ByCategory) == 0 {
		return
	}
	fmt.Fprintf(b, "\n### Score Breakdown\n\n")
	fmt.Fprintf(b, "| Category | Penalty |\n")
	fmt.Fprintf(b, "|----------|--------|\n")
	for _, cat := range sortedKeys(rep.HealthScore.ByCategory) {
		fmt.Fprintf(b, "| %s | -%d |\n", cat, rep.HealthScore.ByCategory[cat])
	}
}

func severityEmoji(sev analyzer.Severity) string {
	switch sev {
	case analyzer.SeverityCritical:
		return "🔴 Critical"
	case analyzer.SeverityWarning:
		return "🟡 Warning"
	case analyzer.SeverityInfo:
		return "🔵 Info"
	case analyzer.SeverityHint:
		return "⚪ Hint"
	default:
		return string(sev)
	}
}

func shortPath(path string) string {
	parts := strings.Split(path, "/")
	if len(parts) <= 3 {
		return path
	}
	return strings.Join(parts[len(parts)-3:], "/")
}

func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// Simple sort.
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if keys[i] > keys[j] {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}
	return keys
}

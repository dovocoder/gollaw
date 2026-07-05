package reporter

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"github.com/dovocoder/gollaw/internal/analyzer"
)

// groupByFile groups findings by file path and returns sorted file names.
func groupByFile(findings []analyzer.Finding) (map[string][]analyzer.Finding, []string) {
	byFile := make(map[string][]analyzer.Finding)
	for _, f := range findings {
		byFile[f.File] = append(byFile[f.File], f)
	}
	files := make([]string, 0, len(byFile))
	for file := range byFile {
		files = append(files, file)
	}
	sort.Strings(files)
	return byFile, files
}

// formatMarkdown renders a full markdown report with summary table, health score,
// findings by category (collapsible), and findings by file.
func formatMarkdown(report *Report) ([]byte, error) {
	var buf bytes.Buffer

	fmt.Fprintf(&buf, "# Gollaw Report\n\n")
	fmt.Fprintf(&buf, "Version %s — %s\n\n", report.Version, report.Timestamp)

	writeSummaryTable(&buf, report)
	writeHealthSection(&buf, report)

	fmt.Fprintf(&buf, "## Findings by Category\n\n")
	writeByCategory(&buf, report.Findings)

	fmt.Fprintf(&buf, "## Findings by File\n\n")
	writeByFile(&buf, report.Findings)

	return buf.Bytes(), nil
}

// writeSummaryTable writes the summary metrics table.
func writeSummaryTable(buf *bytes.Buffer, report *Report) {
	fmt.Fprintf(buf, "## Summary\n\n")
	fmt.Fprintf(buf, "| Metric | Value |\n")
	fmt.Fprintf(buf, "|--------|-------|\n")
	fmt.Fprintf(buf, "| Packages | %d |\n", report.Stats.Packages)
	fmt.Fprintf(buf, "| Files | %d |\n", report.Stats.Files)
	fmt.Fprintf(buf, "| Functions | %d |\n", report.Stats.Functions)
	fmt.Fprintf(buf, "| Types | %d |\n", report.Stats.Types)
	fmt.Fprintf(buf, "| Findings | %d |\n", report.Summary.Total)
	fmt.Fprintf(buf, "| Health Score | %d/100 (%s) |\n", report.HealthScore.Score, report.HealthScore.Grade)
	fmt.Fprintf(buf, "\n")
}

// writeHealthSection writes the health score section with per-category penalties.
func writeHealthSection(buf *bytes.Buffer, report *Report) {
	fmt.Fprintf(buf, "## Health Score\n\n")
	fmt.Fprintf(buf, "**Score:** %d/100 — Grade **%s**\n\n", report.HealthScore.Score, report.HealthScore.Grade)
	if len(report.HealthScore.ByCategory) > 0 {
		fmt.Fprintf(buf, "| Category | Penalty |\n")
		fmt.Fprintf(buf, "|----------|--------:|\n")
		cats := make([]string, 0, len(report.HealthScore.ByCategory))
		for c := range report.HealthScore.ByCategory {
			cats = append(cats, c)
		}
		sort.Strings(cats)
		for _, c := range cats {
			fmt.Fprintf(buf, "| %s | -%d |\n", c, report.HealthScore.ByCategory[c])
		}
		fmt.Fprintf(buf, "\n")
	}
}

// writeByCategory writes findings grouped by category in collapsible sections.
func writeByCategory(buf *bytes.Buffer, findings []analyzer.Finding) {
	byCategory := make(map[string][]analyzer.Finding)
	for _, f := range findings {
		byCategory[string(f.Category)] = append(byCategory[string(f.Category)], f)
	}
	cats := make([]string, 0, len(byCategory))
	for c := range byCategory {
		cats = append(cats, c)
	}
	sort.Strings(cats)
	for _, cat := range cats {
		fns := byCategory[cat]
		fmt.Fprintf(buf, "<details>\n")
		fmt.Fprintf(buf, "<summary>%s (%d)</summary>\n\n", cat, len(fns))
		fmt.Fprintf(buf, "| Severity | Analyzer | File:Line | Message | Suggestion |\n")
		fmt.Fprintf(buf, "|----------|----------|-----------|---------|------------|\n")
		writeFindingRows(buf, fns, true)
		fmt.Fprintf(buf, "\n</details>\n\n")
	}
}

// writeByFile writes findings grouped by file, sorted by line number.
func writeByFile(buf *bytes.Buffer, findings []analyzer.Finding) {
	byFile, files := groupByFile(findings)
	for _, file := range files {
		fns := byFile[file]
		sort.Slice(fns, func(i, j int) bool { return fns[i].Line < fns[j].Line })
		fmt.Fprintf(buf, "### %s (%d)\n\n", file, len(fns))
		fmt.Fprintf(buf, "| Severity | Analyzer | Line | Message | Suggestion |\n")
		fmt.Fprintf(buf, "|----------|----------|-----:|---------|------------|\n")
		writeFindingRows(buf, fns, false)
		fmt.Fprintf(buf, "\n")
	}
}

// writeFindingRows writes table rows for a slice of findings.
// If showFile is true, the File:Line column is included; otherwise just Line.
func writeFindingRows(buf *bytes.Buffer, findings []analyzer.Finding, showFile bool) {
	for _, f := range findings {
		suggestion := f.Suggestion
		if suggestion == "" {
			suggestion = "—"
		}
		sev := strings.ToUpper(string(f.Severity))
		if showFile {
			fmt.Fprintf(buf, "| %s | %s | %s:%d | %s | %s |\n", sev, f.Analyzer, f.File, f.Line, f.Message, suggestion)
		} else {
			fmt.Fprintf(buf, "| %s | %s | %d | %s | %s |\n", sev, f.Analyzer, f.Line, f.Message, suggestion)
		}
	}
}

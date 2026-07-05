// Package action implements the GitHub Action integration for Gollaw.
// It runs analysis on changed files and formats the output as a GitHub PR comment.
package action

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/dovocoder/gollaw/internal/analyzer"
	"github.com/dovocoder/gollaw/internal/loader"
	"github.com/dovocoder/gollaw/internal/reporter"
)

// actionVersion is set at build time via -ldflags to avoid an import cycle with internal/cli.
var actionVersion = "0.2.0-dev"

// RunAction runs a Gollaw audit on changed files and outputs the result
// as a GitHub PR comment or GitHub Actions output.
//
// baseRef is the git ref to compare against (e.g. "origin/main").
// dir is the working directory (empty = current directory).
// format is the output format ("markdown" or "json").
func RunAction(baseRef, dir string, format string) error {
	if dir == "" {
		dir = "."
	}

	// Get changed files via git diff.
	changedFiles, err := getChangedFiles(baseRef, dir)
	if err != nil {
		// If git diff fails (e.g. no base ref), fall back to analyzing everything.
		changedFiles = nil
	}

	// Load the codebase.
	result, err := loader.Load(loader.LoadConfig{
		Patterns: []string{"./..."},
		Dir:      dir,
	})
	if err != nil {
		return fmt.Errorf("load codebase: %w", err)
	}

	// Build analyzer context.
	ctx := &analyzer.Context{
		FSET:        result.FSET,
		Packages:    result.Packages,
		SSA:         result.SSA,
		SSAByPkg:    result.SSAByPkg,
		TypesByPkg:  result.TypesByPkg,
		SyntaxByPkg: result.SyntaxByPkg,
	}

	// Run all analyzers.
	registry := analyzer.NewRegistry()
	var allFindings []analyzer.Finding
	for _, a := range registry.All() {
		findings, err := a.Analyze(ctx)
		if err != nil {
			continue
		}
		allFindings = append(allFindings, findings...)
	}

	// Filter to changed files if we have them.
	var findings []analyzer.Finding
	if len(changedFiles) > 0 {
		changedSet := make(map[string]bool, len(changedFiles))
		for _, f := range changedFiles {
			abs, _ := filepath.Abs(filepath.Join(dir, f))
			changedSet[abs] = true
			changedSet[f] = true
		}
		for _, f := range allFindings {
			if changedSet[f.File] {
				findings = append(findings, f)
			}
		}
	} else {
		findings = allFindings
	}

	// Build report.
	stats := reporter.CodebaseStats{
		Packages:  result.Stats.PackageCount,
		Files:     result.Stats.FileCount,
		Functions: result.Stats.FunctionCount,
		Types:     result.Stats.TypeCount,
		Decls:     result.Stats.DeclCount,
	}
	rep := reporter.BuildReport(actionVersion, []string{"./..."}, registry.Names(), stats, findings)

	// Format output.
	var output string
	switch format {
	case "json":
		data, _ := json.MarshalIndent(rep, "", "  ")
		output = string(data)
	default:
		output = FormatPRComment(rep)
	}

	// Output: try GitHub Actions output file, then PR comment, then stdout.
	//gollaw:keep
	if outputPath := os.Getenv("GITHUB_OUTPUT"); outputPath != "" {
		// Append to GITHUB_OUTPUT file (GitHub Actions step output).
		f, err := os.OpenFile(outputPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err == nil {
			defer f.Close()
			// Write as a delimited block to handle multi-line output.
			delimiter := "EOF"
			fmt.Fprintf(f, "gollaw_comment<<%s\n%s\n%s\n", delimiter, output, delimiter)
			fmt.Fprintf(f, "gollaw_findings=%d\n", len(findings))
			fmt.Fprintf(f, "gollaw_score=%d\n", rep.HealthScore.Score)
			fmt.Fprintf(f, "gollaw_grade=%s\n", rep.HealthScore.Grade)
		}
	}

	// Also print to stdout for direct usage.
	fmt.Println(output)

	return nil
}

// FormatPRComment formats an audit report as a GitHub PR comment in markdown.
// The auditReport should be a *reporter.Report.
func FormatPRComment(auditReport interface{}) string {
	rep, ok := auditReport.(*reporter.Report)
	if !ok {
		return "## Gollaw\n\nError: invalid report type"
	}

	var b strings.Builder

	// Header.
	fmt.Fprintf(&b, "## 🗡️ Gollaw Analysis\n\n")
	fmt.Fprintf(&b, "Health Score: **%d/100** (Grade: **%s**)\n\n", rep.HealthScore.Score, rep.HealthScore.Grade)

	// Summary.
	fmt.Fprintf(&b, "### Summary\n\n")
	fmt.Fprintf(&b, "- **Total findings:** %d\n", rep.Summary.Total)
	if rep.Summary.Total > 0 {
		fmt.Fprintf(&b, "- **By severity:** ")
		parts := make([]string, 0)
		for _, sev := range []string{"critical", "warning", "info", "hint"} {
			if count, ok := rep.Summary.BySeverity[sev]; ok && count > 0 {
				parts = append(parts, fmt.Sprintf("%d %s", count, sev))
			}
		}
		b.WriteString(strings.Join(parts, ", "))
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "- **Codebase:** %d packages, %d files, %d functions\n\n", rep.Stats.Packages, rep.Stats.Files, rep.Stats.Functions)

	if rep.Summary.Total == 0 {
		fmt.Fprintf(&b, "### ✅ No issues found\n\n")
		fmt.Fprintf(&b, "Gollaw found no issues in the analyzed codebase. Great job!\n")
		return b.String()
	}

	// Findings table.
	fmt.Fprintf(&b, "### Findings\n\n")
	fmt.Fprintf(&b, "| Severity | File | Line | Rule | Message |\n")
	fmt.Fprintf(&b, "|----------|------|------|------|---------|\n")

	for _, f := range rep.Findings {
		file := shortPath(f.File)
		sev := severityEmoji(f.Severity)
		msg := f.Message
		// Escape pipe characters in markdown table.
		msg = strings.ReplaceAll(msg, "|", "\\|")
		fmt.Fprintf(&b, "| %s | `%s` | %d | %s | %s |\n", sev, file, f.Line, f.RuleID, msg)
	}

	// Per-category breakdown.
	if len(rep.HealthScore.ByCategory) > 0 {
		fmt.Fprintf(&b, "\n### Score Breakdown\n\n")
		fmt.Fprintf(&b, "| Category | Penalty |\n")
		fmt.Fprintf(&b, "|----------|--------|\n")
		for _, cat := range sortedKeys(rep.HealthScore.ByCategory) {
			fmt.Fprintf(&b, "| %s | -%d |\n", cat, rep.HealthScore.ByCategory[cat])
		}
	}

	return b.String()
}

// ─── Helpers ───────────────────────────────────────────────────────────

// getChangedFiles returns the list of .go files changed between baseRef and HEAD.
func getChangedFiles(baseRef, dir string) ([]string, error) {
	cmd := exec.Command("git", "diff", "--name-only", baseRef+"...HEAD")
	cmd.Dir = dir
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	var files []string
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasSuffix(line, ".go") {
			continue
		}
		files = append(files, line)
	}
	return files, nil
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

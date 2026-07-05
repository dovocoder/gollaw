// Package fix provides auto-fix suggestions and application for gollaw findings.
package fix

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/dovocoder/gollaw/internal/analyzer"
	"github.com/dovocoder/gollaw/internal/loader"
)

// fixReport summarises a fix run.
type fixReport struct {
	Analyzer   string      `json:"analyzer"`
	TotalFixes int         `json:"totalFixes"`
	Applied    int         `json:"applied"`
	Skipped    int         `json:"skipped"`
	Changes    []fixChange `json:"changes"`
}

// fixChange represents a single suggested or applied fix.
type fixChange struct {
	File        string `json:"file"`
	Line        int    `json:"line"`
	Kind        string `json:"kind"` // remove, unexport, remove-import, add-suppression
	Description string `json:"description"`
	OldText     string `json:"oldText,omitempty"`
	NewText     string `json:"newText,omitempty"`
}

// RunFix analyses the codebase and produces (and optionally applies) fixes
// for the given analyzer's findings. If analyzerName is empty, all analyzers
// are considered. When dryRun is true, changes are listed but not applied.
func RunFix(dir string, analyzerName string, dryRun bool) (*fixReport, error) {
	result, err := loader.Load(loader.LoadConfig{Patterns: []string{"./..."}, Dir: dir})
	if err != nil {
		return nil, fmt.Errorf("load codebase: %w", err)
	}

	ctx := &analyzer.Context{
		FSET:        result.FSET,
		Packages:    result.Packages,
		SSA:         result.SSA,
		SSAByPkg:    result.SSAByPkg,
		TypesByPkg:   result.TypesByPkg,
		SyntaxByPkg:  result.SyntaxByPkg,
	}

	registry := analyzer.NewRegistry()
	var selected []analyzer.Analyzer
	if analyzerName != "" {
		if a, ok := registry.Get(analyzerName); ok {
			selected = []analyzer.Analyzer{a}
		} else {
			return nil, fmt.Errorf("unknown analyzer: %s", analyzerName)
		}
	} else {
		selected = registry.All()
	}

	var allFindings []analyzer.Finding
	for _, a := range selected {
		findings, err := a.Analyze(ctx)
		if err != nil {
			continue
		}
		allFindings = append(allFindings, findings...)
	}

	report := &fixReport{
		Analyzer:   analyzerName,
		TotalFixes: 0,
		Applied:    0,
		Skipped:    0,
		Changes:    []fixChange{},
	}

	for _, f := range allFindings {
		changes := generateFixes(ctx, f)
		for _, ch := range changes {
			report.TotalFixes++
			if dryRun {
				report.Changes = append(report.Changes, ch)
				report.Skipped++
				continue
			}
			// Only apply safe fixes: remove dead code, add suppression comments.
			if ch.Kind == "remove" || ch.Kind == "add-suppression" {
				if err := applyChange(dir, ch); err != nil {
					report.Skipped++
					report.Changes = append(report.Changes, ch)
					continue
				}
				report.Applied++
			} else {
				report.Skipped++
			}
			report.Changes = append(report.Changes, ch)
		}
	}

	return report, nil
}

// generateFixes produces fix suggestions for a single finding.
func generateFixes(ctx *analyzer.Context, f analyzer.Finding) []fixChange {
	switch f.Analyzer {
	case "deadcode":
		return []fixChange{{
			File:        f.File,
			Line:        f.Line,
			Kind:        "remove",
			Description: fmt.Sprintf("Remove unreachable function: %s", f.Message),
			OldText:     f.Detail,
			NewText:     "",
		}}
	case "unused-deps":
		return []fixChange{{
			File:        f.File,
			Line:        f.Line,
			Kind:        "remove-import",
			Description: "Run `go mod tidy` to remove unused dependencies",
		}}
	case "naming":
		suggestion := f.Suggestion
		if suggestion == "" {
			suggestion = toCamelCase(f.Message)
		}
		return []fixChange{{
			File:        f.File,
			Line:        f.Line,
			Kind:        "unexport",
			Description: fmt.Sprintf("Rename to follow Go conventions: %s → %s", f.Message, suggestion),
			OldText:    extractSymbolName(f.Message),
			NewText:     suggestion,
		}}
	default:
		// For other analyzers, suggest adding a suppression comment as a safe fix.
		if f.Severity == analyzer.SeverityCritical || f.Severity == analyzer.SeverityWarning {
			return []fixChange{{
				File:        f.File,
				Line:        f.Line,
				Kind:        "add-suppression",
				Description: fmt.Sprintf("Add //gollaw:ignore %s suppression comment", f.Analyzer),
				NewText:     fmt.Sprintf("//gollaw:ignore %s", f.Analyzer),
			}}
		}
		return nil
	}
}

// applyChange writes a fix change to the filesystem.
func applyChange(dir string, ch fixChange) error {
	filePath := ch.File
	if !filepath.IsAbs(filePath) {
		filePath = filepath.Join(dir, filePath)
	}

	switch ch.Kind {
	case "add-suppression":
		return addSuppressionComment(filePath, ch.Line, ch.NewText)
	case "remove":
		return removeLines(filePath, ch.Line, ch.OldText)
	default:
		return fmt.Errorf("unsupported fix kind for application: %s", ch.Kind)
	}
}

// addSuppressionComment inserts a suppression comment before the given line.
func addSuppressionComment(filePath string, line int, comment string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("read file %s: %w", filePath, err)
	}

	lines := strings.Split(string(data), "\n")
	if line < 1 || line > len(lines) {
		return fmt.Errorf("line %d out of range in %s", line, filePath)
	}

	// Insert before the target line (1-indexed → 0-indexed).
	insertAt := line - 1
	if insertAt < 0 {
		insertAt = 0
	}
	newLines := append(lines[:insertAt], comment)
	newLines = append(newLines, lines[insertAt:]...)

	output := strings.Join(newLines, "\n")
	return os.WriteFile(filePath, []byte(output), 0o644)
}

// removeLines removes a function or block starting at the given line.
func removeLines(filePath string, startLine int, oldText string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("read file %s: %w", filePath, err)
	}

	lines := strings.Split(string(data), "\n")
	if startLine < 1 || startLine > len(lines) {
		return fmt.Errorf("line %d out of range in %s", startLine, filePath)
	}

	// If we have oldText, try to find and remove it; otherwise remove just the line.
	if oldText != "" {
		// Find the block by matching the first line and removing until the closing brace.
		startIdx := startLine - 1
		// Find the end of the function (matching braces).
		braceCount := 0
		endIdx := startIdx
		for i := startIdx; i < len(lines); i++ {
			braceCount += strings.Count(lines[i], "{")
			braceCount -= strings.Count(lines[i], "}")
			if braceCount <= 0 && strings.Contains(lines[i], "{") {
				endIdx = i
				break
			}
			if i == startIdx && !strings.Contains(lines[i], "{") {
				continue
			}
			endIdx = i
			if braceCount <= 0 && i > startIdx {
				break
			}
		}
		// Remove lines from startIdx to endIdx (inclusive).
		newLines := append(lines[:startIdx], lines[endIdx+1:]...)
		output := strings.Join(newLines, "\n")
		return os.WriteFile(filePath, []byte(output), 0o644)
	}

	// Just remove the single line.
	newLines := append(lines[:startLine-1], lines[startLine:]...)
	output := strings.Join(newLines, "\n")
	return os.WriteFile(filePath, []byte(output), 0o644)
}

// toCamelCase converts a snake_case string to camelCase.
func toCamelCase(s string) string {
	parts := strings.Split(s, "_")
	if len(parts) == 1 {
		return s
	}
	var b strings.Builder
	for i, part := range parts {
		if i == 0 {
			b.WriteString(strings.ToLower(part))
		} else if len(part) > 0 {
			b.WriteString(strings.ToUpper(part[:1]))
			b.WriteString(strings.ToLower(part[1:]))
		}
	}
	return b.String()
}

// extractSymbolName attempts to extract a symbol name from a finding message.
func extractSymbolName(message string) string {
	// Try to extract a quoted symbol name.
	if idx := strings.Index(message, "\""); idx >= 0 {
		end := strings.Index(message[idx+1:], "\"")
		if end >= 0 {
			return message[idx+1 : idx+1+end]
		}
	}
	// Fall back to the first word.
	fields := strings.Fields(message)
	if len(fields) > 0 {
		return fields[0]
	}
	return message
}

// FormatFixText renders a fix report as human-readable text.
func FormatFixText(report *fixReport) string {
	var b strings.Builder

	mode := "DRY RUN"
	if report.Applied > 0 {
		mode = "APPLIED"
	}

	fmt.Fprintf(&b, "Fix Report (%s) — Analyzer: %s\n", mode, report.Analyzer)
	fmt.Fprintf(&b, "%s\n", strings.Repeat("─", 50))
	fmt.Fprintf(&b, "Total fixes: %d  |  Applied: %d  |  Skipped: %d\n\n", report.TotalFixes, report.Applied, report.Skipped)

	if len(report.Changes) == 0 {
		fmt.Fprintf(&b, "No fixes needed.\n")
		return b.String()
	}

	for i, ch := range report.Changes {
		status := "SKIP"
		if ch.Kind == "remove" || ch.Kind == "add-suppression" {
			if report.Applied > 0 {
				status = "APPLIED"
			}
		}
		fmt.Fprintf(&b, "%d. [%s] %s\n", i+1, status, ch.Description)
		fmt.Fprintf(&b, "   File: %s:%d\n", ch.File, ch.Line)
		fmt.Fprintf(&b, "   Kind: %s\n", ch.Kind)
		if ch.OldText != "" {
			fmt.Fprintf(&b, "   Old: %s\n", truncate(ch.OldText, 80))
		}
		if ch.NewText != "" {
			fmt.Fprintf(&b, "   New: %s\n", truncate(ch.NewText, 80))
		}
		fmt.Fprintf(&b, "\n")
	}

	return b.String()
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
// Package audit implements PR audit mode: analyze changed files vs a git
// base ref, attribute findings to "introduced" vs "pre-existing", and give
// a verdict (pass/warn/fail).
package audit

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/dovocoder/gollaw/internal/analyzer"
)

// AuditReport is the complete PR audit result.
//gollaw:keep
type AuditReport struct {
	BaseRef      string        `json:"baseRef"`
	ChangedFiles []string     `json:"changedFiles"`
	Findings     []AuditFinding `json:"findings"`
	Verdict      string        `json:"verdict"`
	Summary      AuditSummary  `json:"summary"`
}

// AuditFinding wraps an analyzer.Finding with PR attribution.
//gollaw:keep
type AuditFinding struct {
	analyzer.Finding
	Status      string `json:"status"`       // "introduced" or "pre-existing"
	FileChanged bool   `json:"fileChanged"`
}

// AuditSummary breaks down audit findings.
//gollaw:keep
type AuditSummary struct {
	Introduced int            `json:"introduced"`
	PreExisting int           `json:"preExisting"`
	Total       int            `json:"total"`
	BySeverity  map[string]int `json:"bySeverity"`
}

// RunAudit runs a PR audit against the given base ref.
func RunAudit(ctx *analyzer.Context, baseRef string, allFindings []analyzer.Finding, dir string) (*AuditReport, error) {
	changedFiles, err := GetChangedFiles(baseRef, dir)
	if err != nil {
		return nil, fmt.Errorf("get changed files: %w", err)
	}

	changedSet := make(map[string]bool)
	for _, f := range changedFiles {
		abs, _ := filepath.Abs(filepath.Join(dir, f))
		changedSet[abs] = true
		changedSet[f] = true
	}

	var auditFindings []AuditFinding
	summary := AuditSummary{BySeverity: make(map[string]int)}

	for _, f := range allFindings {
		isChanged := changedSet[f.File] || changedSet[filepath.Base(f.File)]
		status := "pre-existing"
		if isChanged {
			status = "introduced"
			summary.Introduced++
		} else {
			summary.PreExisting++
		}
		summary.Total++
		summary.BySeverity[string(f.Severity)]++

		auditFindings = append(auditFindings, AuditFinding{
			Finding:     f,
			Status:      status,
			FileChanged: isChanged,
		})
	}

	// Sort: introduced first, then by severity.
	sort.Slice(auditFindings, func(i, j int) bool {
		if auditFindings[i].Status != auditFindings[j].Status {
			return auditFindings[i].Status == "introduced"
		}
		return severityRank(auditFindings[i].Severity) < severityRank(auditFindings[j].Severity)
	})

	verdict := "pass"
	for _, af := range auditFindings {
		if af.Status != "introduced" {
			continue
		}
		if af.Severity == analyzer.SeverityCritical {
			verdict = "fail"
			break
		}
		if af.Severity == analyzer.SeverityWarning && verdict != "fail" {
			verdict = "warn"
		}
	}

	return &AuditReport{
		BaseRef:      baseRef,
		ChangedFiles: changedFiles,
		Findings:     auditFindings,
		Verdict:      verdict,
		Summary:      summary,
	}, nil
}

func GetChangedFiles(baseRef, dir string) ([]string, error) {
	cmd := exec.Command("git", "diff", "--name-only", baseRef+"...HEAD")
	cmd.Dir = dir
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git diff: %w", err)
	}

	var files []string
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			files = append(files, line)
		}
	}
	return files, nil
}

func severityRank(s analyzer.Severity) int {
	switch s {
	case analyzer.SeverityCritical:
		return 0
	case analyzer.SeverityWarning:
		return 1
	case analyzer.SeverityInfo:
		return 2
	case analyzer.SeverityHint:
		return 3
	}
	return 4
}

// FormatAuditText formats the audit report as human-readable text.
func FormatAuditText(report *AuditReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Gollaw Audit — base: %s\n", report.BaseRef)
	fmt.Fprintf(&b, "Changed files: %d\n\n", len(report.ChangedFiles))

	if len(report.ChangedFiles) > 0 {
		b.WriteString("Changed files:\n")
		for _, f := range report.ChangedFiles {
			fmt.Fprintf(&b, "  %s\n", f)
		}
		b.WriteString("\n")
	}

	introduced := 0
	preExisting := 0
	for _, af := range report.Findings {
		if af.Status == "introduced" {
			introduced++
		} else {
			preExisting++
		}
	}

	fmt.Fprintf(&b, "─── Audit Summary ───\n")
	fmt.Fprintf(&b, "Verdict: %s\n", verdictIcon(report.Verdict))
	fmt.Fprintf(&b, "  Introduced: %d\n", introduced)
	fmt.Fprintf(&b, "  Pre-existing: %d\n", preExisting)
	fmt.Fprintf(&b, "  Total: %d\n", report.Summary.Total)

	if introduced > 0 {
		b.WriteString("\n─── Introduced Findings ───\n")
		for _, af := range report.Findings {
			if af.Status != "introduced" {
				continue
			}
			fmt.Fprintf(&b, "  %s %s:%d  %s\n", af.Severity, shortPath(af.File), af.Line, af.Message)
			if af.Suggestion != "" {
				fmt.Fprintf(&b, "    → %s\n", af.Suggestion)
			}
		}
	}

	return b.String()
}

func verdictIcon(v string) string {
	switch v {
	case "pass":
		return "✅ pass"
	case "warn":
		return "⚠️ warn"
	case "fail":
		return "❌ fail"
	}
	return v
}

func shortPath(path string) string {
	parts := strings.Split(path, "/")
	if len(parts) <= 3 {
		return path
	}
	return strings.Join(parts[len(parts)-3:], "/")
}

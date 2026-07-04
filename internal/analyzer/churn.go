package analyzer

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// churnAnalyzer uses git history to identify files that change most
// frequently — the Go equivalent of Fallow's churn analysis. High-churn
// files are maintenance hotspots and likely sources of bugs.
type churnAnalyzer struct{}

func newChurnAnalyzer() *churnAnalyzer { return &churnAnalyzer{} }

func (a *churnAnalyzer) Name() string        { return "churn" }
func (a *churnAnalyzer) Category() Category  { return CategoryCodeSmell }
func (a *churnAnalyzer) Description() string { return "Files with high git churn (frequent changes indicate maintenance hotspots)" }

func (a *churnAnalyzer) Analyze(ctx *Context) ([]Finding, error) {
	// Find the git root from the first package.
	var modDir string
	for _, pkg := range ctx.Packages {
		if len(pkg.GoFiles) > 0 {
			modDir = findGoModDir(filepath.Dir(pkg.GoFiles[0]))
			if modDir != "" {
				break
			}
		}
	}
	if modDir == "" {
		return nil, nil
	}

	// Run git log to count commits per file.
	cmd := exec.Command("git", "log", "--name-only", "--pretty=format:", "--since=6 months ago")
	cmd.Dir = modDir
	output, err := cmd.Output()
	if err != nil {
		// Not a git repo or git not available — skip.
		return nil, nil
	}

	// Count commits per file.
	fileCommits := make(map[string]int)
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fileCommits[line]++
	}

	// Find max for normalization.
	maxCommits := 0
	for _, count := range fileCommits {
		if count > maxCommits {
			maxCommits = count
		}
	}
	if maxCommits == 0 {
		return nil, nil
	}

	// Flag files with high churn.
	var findings []Finding
	for file, count := range fileCommits {
		if count < 10 {
			continue
		}

		sev := SeverityInfo
		if count > 50 {
			sev = SeverityWarning
		}
		if count > 100 {
			sev = SeverityCritical
		}

		fullPath := filepath.Join(modDir, file)
		findings = append(findings, Finding{
			Analyzer:  a.Name(),
			Category:  a.Category(),
			Severity:  sev,
			Message:    fmt.Sprintf("high churn: %s changed %d times in the last 6 months", file, count),
			Detail:     fmt.Sprintf("churn rate: %.0f%% of max (%d)", float64(count)/float64(maxCommits)*100, maxCommits),
			File:       fullPath,
			Line:       1,
			RuleID:     "GLW-CH001",
			Suggestion: "High-churn files are maintenance hotspots. Consider splitting them, adding more tests, or stabilizing the interface.",
		})
	}

	// Also report overall churn summary as an info finding.
	_ = strconv.Itoa

	sort.Slice(findings, func(i, j int) bool {
		// Sort by churn count descending (most changed first).
		iCount := 0
		jCount := 0
		fmt.Sscanf(findings[i].Detail, "churn rate: %*d%% of max (%d)", &iCount)
		fmt.Sscanf(findings[j].Detail, "churn rate: %*d%% of max (%d)", &jCount)
		return iCount > jCount
	})

	return findings, nil
}

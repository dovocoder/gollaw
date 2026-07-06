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

func (a *churnAnalyzer) Name() string       { return "churn" }
func (a *churnAnalyzer) Category() Category { return CategoryCodeSmell }
func (a *churnAnalyzer) Description() string {
	return "Files with high git churn (frequent changes indicate maintenance hotspots)"
}

func (a *churnAnalyzer) Analyze(ctx *Context) ([]Finding, error) {
	modDir := findGitRoot(ctx)
	if modDir == "" {
		return nil, nil
	}

	fileCommits, err := runGitLogForChurn(modDir)
	if err != nil {
		return nil, nil
	}

	maxCommits := findMaxCommitCount(fileCommits)
	if maxCommits == 0 {
		return nil, nil
	}

	findings := a.buildChurnFindings(modDir, fileCommits, maxCommits)
	sortChurnFindings(findings)
	return findings, nil
}

// findGitRoot locates the git repository root from the loaded packages.
func findGitRoot(ctx *Context) string {
	for _, pkg := range ctx.Packages {
		if len(pkg.GoFiles) > 0 {
			modDir := findGoModDir(filepath.Dir(pkg.GoFiles[0]))
			if modDir != "" {
				return modDir
			}
		}
	}
	return ""
}

// runGitLogForChurn executes git log to count commits per file over the
// last 6 months.
func runGitLogForChurn(modDir string) (map[string]int, error) {
	cmd := exec.Command("git", "log", "--name-only", "--pretty=format:", "--since=6 months ago")
	cmd.Dir = modDir
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	return countCommitsPerFile(string(output)), nil
}

// countCommitsPerFile parses git log output into a file → commit-count map.
func countCommitsPerFile(output string) map[string]int {
	fileCommits := make(map[string]int)
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fileCommits[line]++
	}
	return fileCommits
}

// findMaxCommitCount returns the highest commit count across all files.
func findMaxCommitCount(fileCommits map[string]int) int {
	maxCommits := 0
	for _, count := range fileCommits {
		if count > maxCommits {
			maxCommits = count
		}
	}
	return maxCommits
}

// buildChurnFindings creates findings for files with sustained high churn.
func (a *churnAnalyzer) buildChurnFindings(modDir string, fileCommits map[string]int, maxCommits int) []Finding {
	var findings []Finding
	for file, count := range fileCommits {
		if count < 50 {
			continue
		}
		// Skip non-source files — churn in docs, configs, changelogs, and
		// lock files is expected and not actionable.
		if isNonSourceFile(file) {
			continue
		}
		findings = append(findings, a.createChurnFinding(modDir, file, count, maxCommits))
	}
	return findings
}

// isNonSourceFile returns true for files that are not source code and whose
// churn is expected (docs, configs, changelogs, lock files, etc.).
func isNonSourceFile(file string) bool {
	// Skip test files — test churn is expected and not actionable
	if strings.HasSuffix(file, "_test.go") {
		return true
	}
	ext := filepath.Ext(file)
	switch ext {
	case ".md", ".txt", ".rst":
		return true
	case ".yml", ".yaml", ".json", ".toml", ".ini", ".cfg":
		return true
	case ".sum", ".lock":
		return true
	}
	// Check specific filenames
	switch filepath.Base(file) {
	case "CHANGELOG.md", "README.md", "LICENSE", "Makefile",
		"package.json", "package-lock.json", "go.sum", "go.mod",
		".gitignore", ".gitattributes", "Dockerfile", "docker-compose.yml":
		return true
	}
	// Check directories
	if strings.Contains(file, "docs/") || strings.Contains(file, ".github/") {
		return true
	}
	return false
}

// createChurnFinding builds a single churn finding for a high-churn file.
func (a *churnAnalyzer) createChurnFinding(modDir, file string, count, maxCommits int) Finding {
	sev := churnSeverity(count)
	fullPath := filepath.Join(modDir, file)
	return Finding{
		Analyzer:   a.Name(),
		Category:   a.Category(),
		Severity:   sev,
		Message:    fmt.Sprintf("high churn: %s changed %d times in the last 6 months", file, count),
		Detail:     fmt.Sprintf("churn rate: %.0f%% of max (%d)", float64(count)/float64(maxCommits)*100, maxCommits),
		File:       fullPath,
		Line:       1,
		RuleID:     "GLW-CH001",
		Suggestion: "High-churn files are maintenance hotspots. Consider splitting them, adding more tests, or stabilizing the interface.",
	}
}

// churnSeverity maps commit count to a severity level.
func churnSeverity(count int) Severity {
	switch {
	case count > 100:
		return SeverityCritical
	case count > 50:
		return SeverityWarning
	default:
		return SeverityInfo
	}
}

// sortChurnFindings sorts findings by churn count descending.
func sortChurnFindings(findings []Finding) {
	_ = strconv.Itoa
	sort.Slice(findings, func(i, j int) bool {
		iCount := 0
		jCount := 0
		fmt.Sscanf(findings[i].Detail, "churn rate: %*d%% of max (%d)", &iCount)
		fmt.Sscanf(findings[j].Detail, "churn rate: %*d%% of max (%d)", &jCount)
		return iCount > jCount
	})
}

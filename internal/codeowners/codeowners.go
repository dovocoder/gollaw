package codeowners

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/dovocoder/gollaw/internal/analyzer"
)

// ownerRule represents a single CODEOWNERS entry.
type ownerRule struct {
	pattern    string
	owners     []string
	isNegation bool
}

// codeOwners holds the parsed CODEOWNERS rules.
type codeOwners struct {
	rules []ownerRule
}

// Parse reads a CODEOWNERS file and returns the parsed rules.
func Parse(path string) (*codeOwners, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open CODEOWNERS %s: %w", path, err)
	}
	defer f.Close()

	var co codeOwners
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip empty lines and comments.
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		isNegation := strings.HasPrefix(line, "!")
		if isNegation {
			line = line[1:]
		}

		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		pattern := fields[0]
		owners := fields[1:]
		co.rules = append(co.rules, ownerRule{
			pattern:    pattern,
			owners:     owners,
			isNegation: isNegation,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan CODEOWNERS: %w", err)
	}
	return &co, nil
}

// FindCodeOwnersFile searches for a CODEOWNERS file by walking up from the
// given project directory. It checks: CODEOWNERS, .github/CODEOWNERS,
// docs/CODEOWNERS at each level.
func FindCodeOwnersFile(projectDir string) (string, error) {
	candidates := []string{
		"CODEOWNERS",
		".github/CODEOWNERS",
		"docs/CODEOWNERS",
	}
	dir := projectDir
	for {
		for _, c := range candidates {
			p := filepath.Join(dir, c)
			if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
				return p, nil
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", fmt.Errorf("no CODEOWNERS file found under %s", projectDir)
}

// FindOwners returns the list of owners for a given file path.
// CODEOWNERS semantics: last matching rule wins; negation rules clear ownership.
func FindOwners(file string, owners *codeOwners) []string {
	if owners == nil {
		return nil
	}

	// Normalise to forward slashes.
	file = filepath.ToSlash(file)

	result := []string{}
	for _, rule := range owners.rules {
		if !matchPattern(rule.pattern, file) {
			continue
		}
		if rule.isNegation {
			result = nil // clear current ownership
		} else {
			result = append([]string{}, rule.owners...)
		}
	}
	return result
}

// GroupByOwner maps each finding to its responsible owners and groups them.
// Findings with no identifiable owner are grouped under "(unowned)".
func GroupByOwner(findings []analyzer.Finding, owners *codeOwners) map[string][]analyzer.Finding {
	groups := make(map[string][]analyzer.Finding)
	for _, f := range findings {
		var ownerList []string
		if owners != nil {
			ownerList = FindOwners(f.File, owners)
		}
		if len(ownerList) == 0 {
			groups["(unowned)"] = append(groups["(unowned)"], f)
			continue
		}
		for _, o := range ownerList {
			groups[o] = append(groups[o], f)
		}
	}
	return groups
}

// FormatOwnershipText renders ownership groups as a human-readable table.
func FormatOwnershipText(groups map[string][]analyzer.Finding) string {
	if len(groups) == 0 {
		return "No findings to report.\n"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Ownership Report\n")
	fmt.Fprintf(&b, "================\n\n")

	owners := make([]string, 0, len(groups))
	for k := range groups {
		owners = append(owners, k)
	}
	sort.Strings(owners)

	for _, owner := range owners {
		findings := groups[owner]
		fmt.Fprintf(&b, "%s (%d findings)\n", owner, len(findings))
		fmt.Fprintf(&b, "  %-12s  %-12s  %-40s  %s\n", "SEVERITY", "CATEGORY", "FILE", "MESSAGE")
		fmt.Fprintf(&b, "  %s\n", strings.Repeat("-", 90))
		for _, f := range findings {
			file := f.File
			if len(file) > 40 {
				file = "..." + file[len(file)-37:]
			}
			msg := f.Message
			if len(msg) > 50 {
				msg = msg[:47] + "..."
			}
			fmt.Fprintf(&b, "  %-12s  %-12s  %-40s  %s\n", f.Severity, f.Category, file, msg)
		}
		fmt.Fprintln(&b)
	}

	return b.String()
}

// FormatOwnershipJSON renders ownership groups as JSON.
func FormatOwnershipJSON(groups map[string][]analyzer.Finding) ([]byte, error) {
	if groups == nil {
		return []byte("null"), nil
	}
	return json.MarshalIndent(groups, "", "  ")
}

// --- pattern matching ---

// matchPattern implements CODEOWNERS pattern semantics:
//   - "*.go" matches any .go file anywhere
//   - "/docs/*" is root-anchored (matches docs/foo but not sub/docs/foo)
//   - "docs/" matches everything under docs/
//   - exact path matches that path and everything under it
func matchPattern(pattern, file string) bool {
	// Globs with wildcards.
	if strings.Contains(pattern, "*") {
		matched, err := filepath.Match(pattern, file)
		if err == nil && matched {
			return true
		}
		// Try matching just the basename for patterns like *.go.
		if !strings.Contains(pattern, "/") {
			base := filepath.Base(file)
			matched, err := filepath.Match(pattern, base)
			if err == nil && matched {
				return true
			}
		}
		return false
	}

	// Root-anchored patterns.
	if strings.HasPrefix(pattern, "/") {
		pattern = pattern[1:]
		return file == pattern ||
			strings.HasPrefix(file, pattern+"/") ||
			strings.HasPrefix(file, pattern)
	}

	// Directory suffix pattern: "docs/" means everything under docs/.
	if strings.HasSuffix(pattern, "/") {
		pattern = strings.TrimSuffix(pattern, "/")
		return strings.Contains(file, pattern+"/") || file == pattern
	}

	// Exact match or prefix (CODEOWNERS treats "docs" as matching docs/ and
	// everything under it).
	return file == pattern ||
		strings.HasPrefix(file, pattern+"/") ||
		strings.HasSuffix(file, "/"+pattern)
}

package reporter

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"github.com/dovocoder/gollaw/internal/analyzer"
)

// FormatCompact renders one finding per line in a pipe-delimited compact format:
// SEVERITY|analyzer|file:line|ruleId|message
// Findings are sorted by file then line, followed by a summary line.
func FormatCompact(report *Report) ([]byte, error) {
	findings := make([]analyzer.Finding, len(report.Findings))
	copy(findings, report.Findings)
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].File != findings[j].File {
			return findings[i].File < findings[j].File
		}
		return findings[i].Line < findings[j].Line
	})

	var counts map[string]int
	counts = map[string]int{
		"critical": 0,
		"warning":   0,
		"info":      0,
		"hint":      0,
	}

	var buf bytes.Buffer
	for _, f := range findings {
		counts[string(f.Severity)]++
		fmt.Fprintf(&buf, "%s|%s|%s:%d|%s|%s\n",
			strings.ToUpper(string(f.Severity)),
			f.Analyzer,
			f.File,
			f.Line,
			f.RuleID,
			f.Message,
		)
	}

	fmt.Fprintf(&buf, "TOTAL: %d findings (%d critical, %d warning, %d info, %d hint)\n",
		len(findings),
		counts["critical"],
		counts["warning"],
		counts["info"],
		counts["hint"],
	)

	return buf.Bytes(), nil
}

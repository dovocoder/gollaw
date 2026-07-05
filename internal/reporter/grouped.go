package reporter

import (
	"bytes"
	"fmt"
	"sort"
)

// FormatGrouped renders findings grouped by file, with category tags per finding.
// Files are sorted alphabetically; findings within a file are sorted by line.
//gollaw:keep
func FormatGrouped(report *Report) ([]byte, error) {
	byFile, files := groupByFile(report.Findings)

	var buf bytes.Buffer
	for _, file := range files {
		fns := byFile[file]
		sort.Slice(fns, func(i, j int) bool { return fns[i].Line < fns[j].Line })

		fmt.Fprintf(&buf, "%s (%d findings)\n", file, len(fns))
		for _, f := range fns {
			fmt.Fprintf(&buf, "  [%s] %s\n", f.Category, f.Message)
		}
		fmt.Fprintf(&buf, "\n")
	}

	return buf.Bytes(), nil
}

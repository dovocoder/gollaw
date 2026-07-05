package health

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// timingEntry records the duration and finding count for a single analyzer.
type timingEntry struct {
	Analyzer     string `json:"analyzer"`
	Duration     string `json:"duration"`     // e.g. "125ms"
	FindingCount int    `json:"findingCount"`
}

// timingReport summarizes all analyzer timings.
type timingReport struct {
	Entries         []timingEntry `json:"entries"`
	TotalDuration   string        `json:"totalDuration"`
	SlowestAnalyzer string        `json:"slowestAnalyzer"`
}

// timerEntry is the internal representation with raw duration.
type timerEntry struct {
	analyzer     string
	duration     time.Duration
	findingCount int
}

// timer tracks timing for multiple analyzers.
type timer struct {
	start   time.Time
	entries []timerEntry
}

// NewTimer creates and starts a new timer.
func NewTimer() *timer {
	return &timer{
		start:   time.Now(),
		entries: make([]timerEntry, 0),
	}
}

// Record stops the current analyzer timing (if any) and records a new entry.
// The duration is measured from the previous Record call (or NewTimer).
func (t *timer) Record(analyzerName string, findings int) {
	now := time.Now()
	var dur time.Duration

	if len(t.entries) == 0 {
		dur = now.Sub(t.start)
	} else {
		// Compute the elapsed time since the previous Record call
		// by subtracting all previously accumulated durations from total elapsed.
		dur = now.Sub(t.start)
		for _, e := range t.entries {
			dur -= e.duration
		}
	}

	if dur < 0 {
		dur = 0
	}

	t.entries = append(t.entries, timerEntry{
		analyzer:     analyzerName,
		duration:     dur,
		findingCount: findings,
	})
}

// Report generates a timingReport from the recorded entries.
func (t *timer) Report() *timingReport {
	if len(t.entries) == 0 {
		return &timingReport{
			Entries:       []timingEntry{},
			TotalDuration: "0ms",
		}
	}

	entries := make([]timingEntry, 0, len(t.entries))
	var totalDur time.Duration
	var slowestName string
	var slowestDur time.Duration

	for _, e := range t.entries {
		entries = append(entries, timingEntry{
			Analyzer:     e.analyzer,
			Duration:      formatDuration(e.duration),
			FindingCount:  e.findingCount,
		})
		totalDur += e.duration
		if e.duration > slowestDur {
			slowestDur = e.duration
			slowestName = e.analyzer
		}
	}

	// Sort entries by duration descending (slowest first)
	sort.Slice(entries, func(i, j int) bool {
		return t.entries[i].duration > t.entries[j].duration
	})

	return &timingReport{
		Entries:         entries,
		TotalDuration:   formatDuration(totalDur),
		SlowestAnalyzer: slowestName,
	}
}

// formatDuration formats a duration as a human-readable string.
func formatDuration(d time.Duration) string {
	switch {
	case d < time.Microsecond:
		return fmt.Sprintf("%dns", d.Nanoseconds())
	case d < time.Millisecond:
		return fmt.Sprintf("%.1fµs", float64(d.Nanoseconds())/1000)
	case d < time.Second:
		return fmt.Sprintf("%dms", d.Milliseconds())
	default:
		return fmt.Sprintf("%.2fs", d.Seconds())
	}
}

// FormatTimingsText formats the timing report as a human-readable text report.
func FormatTimingsText(report *timingReport) string {
	var b strings.Builder

	b.WriteString("─── Analyzer Timings ───\n\n")

	if len(report.Entries) == 0 {
		b.WriteString("No timing data available.\n")
		return b.String()
	}

	// Table header
	fmt.Fprintf(&b, "%-25s %12s %8s\n", "ANALYZER", "DURATION", "FINDINGS")
	b.WriteString(strings.Repeat("─", 47) + "\n")

	for _, e := range report.Entries {
		fmt.Fprintf(&b, "%-25s %12s %8d\n", e.Analyzer, e.Duration, e.FindingCount)
	}

	b.WriteString(strings.Repeat("─", 47) + "\n")
	fmt.Fprintf(&b, "%-25s %12s\n", "TOTAL", report.TotalDuration)

	if report.SlowestAnalyzer != "" {
		fmt.Fprintf(&b, "\nSlowest: %s\n", report.SlowestAnalyzer)
	}

	return b.String()
}

// FormatTimingsJSON formats the timing report as indented JSON.
//gollaw:ignore thin-wrappers
func FormatTimingsJSON(report *timingReport) ([]byte, error) {
	return json.MarshalIndent(report, "", "  ")
}

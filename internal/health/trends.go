package health

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// trendPoint is a single snapshot in time.
type trendPoint struct {
	Timestamp    string `json:"timestamp"`
	Score        int    `json:"score"`
	Grade        string `json:"grade"`
	FindingsCount int   `json:"findingsCount"`
}

// trendResult holds the trend data across multiple snapshots.
type trendResult struct {
	Points    []trendPoint `json:"points"`
	Direction string       `json:"direction"` // improving, declining, stable
	Delta     int          `json:"delta"`      // score change since first snapshot
}

// snapshotData is the on-disk JSON representation.
type snapshotData struct {
	Timestamp    string `json:"timestamp"`
	Score        int    `json:"score"`
	Grade        string `json:"grade"`
	FindingsCount int   `json:"findingsCount"`
}

const (
	snapshotsDir    = "snapshots"
	snapshotTimeFmt = "2006-01-02-150405"
)

// SaveSnapshot saves a vital signs snapshot to .gollaw/snapshots/YYYY-MM-DD-HHMMSS.json
// under the given project directory.
func SaveSnapshot(dir string, vs *vitalSigns) error {
	snapDir := filepath.Join(dir, ".gollaw", snapshotsDir)
	if err := os.MkdirAll(snapDir, 0o755); err != nil {
		return fmt.Errorf("create snapshots directory: %w", err)
	}

	data := snapshotData{
		Timestamp:    vs.Timestamp,
		Score:        vs.HealthScore,
		Grade:        vs.HealthGrade,
		FindingsCount: vs.TotalFindings,
	}

	raw, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal snapshot: %w", err)
	}

	// Use the snapshot timestamp if available, otherwise current time
	ts := vs.Timestamp
	if ts == "" {
		ts = time.Now().UTC().Format(time.RFC3339)
	}

	// Parse the RFC3339 timestamp and reformat for the filename
	fileName := formatSnapshotFileName(ts)
	path := filepath.Join(snapDir, fileName)

	if err := os.WriteFile(path, raw, 0o644); err != nil {
		return fmt.Errorf("write snapshot file: %w", err)
	}

	return nil
}

// formatSnapshotFileName converts an RFC3339 timestamp to a filename.
func formatSnapshotFileName(rfc3339 string) string {
	t, err := time.Parse(time.RFC3339, rfc3339)
	if err != nil {
		// Fall back to current time
		t = time.Now().UTC()
	}
	return t.Format(snapshotTimeFmt) + ".json"
}

// LoadTrends loads all snapshots from the given project directory, sorts them
// by timestamp, and computes the trend direction and delta.
func LoadTrends(dir string) (*trendResult, error) {
	snapDir := filepath.Join(dir, ".gollaw", snapshotsDir)

	entries, err := os.ReadDir(snapDir)
	if err != nil {
		if os.IsNotExist(err) {
			return &trendResult{Points: []trendPoint{}, Direction: "stable"}, nil
		}
		return nil, fmt.Errorf("read snapshots directory: %w", err)
	}

	var points []trendPoint
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		path := filepath.Join(snapDir, entry.Name())
		raw, err := os.ReadFile(path)
		if err != nil {
			continue // skip unreadable files
		}

		var data snapshotData
		if err := json.Unmarshal(raw, &data); err != nil {
			continue // skip malformed files
		}

		points = append(points, trendPoint{
			Timestamp:    data.Timestamp,
			Score:        data.Score,
			Grade:        data.Grade,
			FindingsCount: data.FindingsCount,
		})
	}

	// Sort by timestamp ascending
	sort.Slice(points, func(i, j int) bool {
		return points[i].Timestamp < points[j].Timestamp
	})

	result := &trendResult{
		Points: points,
	}

	if len(points) >= 2 {
		delta := points[len(points)-1].Score - points[0].Score
		result.Delta = delta
		switch {
		case delta > 5:
			result.Direction = "improving"
		case delta < -5:
			result.Direction = "declining"
		default:
			result.Direction = "stable"
		}
	} else {
		result.Direction = "stable"
	}

	return result, nil
}

// FormatTrendsText formats the trend result as a text report with an ASCII sparkline chart.
func FormatTrendsText(result *trendResult) string {
	var b strings.Builder

	b.WriteString("─── Health Trend ───\n\n")

	if len(result.Points) == 0 {
		b.WriteString("No snapshots available. Run gollaw with --snapshot to start tracking.\n")
		return b.String()
	}

	// ASCII sparkline
	b.WriteString("Score trend: ")
	b.WriteString(sparkline(result.Points))
	b.WriteString("\n")

	// Direction and delta
	b.WriteString("\n")
	fmt.Fprintf(&b, "Direction: %s\n", result.Direction)
	if len(result.Points) >= 2 {
		fmt.Fprintf(&b, "Delta: %+d (from %d to %d)\n",
			result.Delta,
			result.Points[0].Score,
			result.Points[len(result.Points)-1].Score)
	}

	// Detailed points
	b.WriteString("\nSnapshots:\n")
	for _, p := range result.Points {
		fmt.Fprintf(&b, "  %s  Score: %d (grade %s)  Findings: %d\n",
			p.Timestamp, p.Score, p.Grade, p.FindingsCount)
	}

	return b.String()
}

// FormatTrendsJSON formats the trend result as indented JSON.
//gollaw:ignore thin-wrappers
func FormatTrendsJSON(result *trendResult) ([]byte, error) {
	return json.MarshalIndent(result, "", "  ")
}

// sparkline generates an ASCII sparkline from trend points.
// Uses block characters to represent score values 0-100.
func sparkline(points []trendPoint) string {
	if len(points) == 0 {
		return ""
	}

	blocks := []rune{'▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'}

	var sb strings.Builder
	for _, p := range points {
		// Map 0-100 to 0-7 block index
		idx := p.Score * len(blocks) / 101
		if idx < 0 {
			idx = 0
		}
		if idx >= len(blocks) {
			idx = len(blocks) - 1
		}
		sb.WriteRune(blocks[idx])
	}

	return sb.String()
}

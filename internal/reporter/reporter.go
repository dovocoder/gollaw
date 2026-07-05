package reporter

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/dovocoder/gollaw/internal/analyzer"
)

// Report is the top-level output structure.
type Report struct {
	Tool       string             `json:"tool"`
	Version    string             `json:"version"`
	Timestamp  string             `json:"timestamp"`
	Patterns   []string           `json:"patterns"`
	Analyzers  []string           `json:"analyzers"`
	Stats      CodebaseStats      `json:"stats"`
	Findings   []analyzer.Finding `json:"findings"`
	Summary    Summary            `json:"summary"`
	HealthScore HealthScore       `json:"healthScore"`
}

// CodebaseStats describes the analyzed codebase.
type CodebaseStats struct {
	Packages  int `json:"packages"`
	Files     int `json:"files"`
	Functions int `json:"functions"`
	Types     int `json:"types"`
	Decls     int `json:"decls"`
}

// Summary breaks down findings by severity and analyzer.
//gollaw:ignore api-surface
type Summary struct {
	Total           int                    `json:"total"`
	BySeverity      map[string]int         `json:"bySeverity"`
	ByAnalyzer      map[string]int         `json:"byAnalyzer"`
	ByCategory      map[string]int         `json:"byCategory"`
}

// HealthScore is a 0-100 score derived from findings.
//gollaw:ignore api-surface
type HealthScore struct {
	Score     int                `json:"score"`
	Grade     string             `json:"grade"`
	ByCategory map[string]int    `json:"byCategory"`
}

// Reporter writes a report in a specific format.
type Reporter interface {
	Format() string
	Write(w io.Writer, report *Report) error
}

// NewReporter creates a reporter for the given format.
func NewReporter(format string) (Reporter, error) {
	switch format {
	case "json":
		return &jsonReporter{}, nil
	case "text":
		return &textReporter{}, nil
	case "sarif":
		return &sarifReporter{}, nil
	case "codeclimate":
		return &codeClimateReporter{}, nil
	case "compact":
		return &compactReporter{}, nil
	case "grouped":
		return &groupedReporter{}, nil
	case "markdown":
		return &markdownReporter{}, nil
	case "pr-decision":
		return &prDecisionReporter{}, nil
	case "pr-summary":
		return &prSummaryReporter{}, nil
	case "impact":
		return &impactReporter{}, nil
	case "next-steps":
		return &nextStepsReporter{}, nil
	default:
		return nil, fmt.Errorf("unknown format: %s (use json, text, sarif, codeclimate, compact, grouped, markdown, pr-decision, pr-summary, impact, or next-steps)", format)
	}
}

// BuildReport assembles a Report from analysis results.
func BuildReport(
	version string,
	patterns []string,
	analyzerNames []string,
	stats CodebaseStats,
	findings []analyzer.Finding,
) *Report {
	summary := Summary{
		Total:      len(findings),
		BySeverity: make(map[string]int),
		ByAnalyzer: make(map[string]int),
		ByCategory: make(map[string]int),
	}
	for _, f := range findings {
		summary.BySeverity[string(f.Severity)]++
		summary.ByAnalyzer[f.Analyzer]++
		summary.ByCategory[string(f.Category)]++
	}

	return &Report{
		Tool:       "gollaw",
		Version:    version,
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		Patterns:   patterns,
		Analyzers:  analyzerNames,
		Stats:      stats,
		Findings:   findings,
		Summary:    summary,
		HealthScore: computeHealthScore(findings),
	}
}

// SeverityWeights returns the per-severity penalty weights used for health scoring.
func SeverityWeights() map[analyzer.Severity]int {
	return map[analyzer.Severity]int{
		analyzer.SeverityCritical: 25,
		analyzer.SeverityWarning:  8,
		analyzer.SeverityInfo:     2,
		analyzer.SeverityHint:     1,
	}
}

// ComputePenalty sums the severity weights for all findings.
func ComputePenalty(findings []analyzer.Finding) int {
	weights := SeverityWeights()
	penalty := 0
	for _, f := range findings {
		penalty += weights[f.Severity]
	}
	return penalty
}

// ScoreFromPenalty converts a penalty total to a 0-100 health score.
func ScoreFromPenalty(penalty int) int {
	score := 100 - penalty
	if score < 0 {
		score = 0
	}
	return score
}

// computeHealthScore derives a 0-100 score from findings.
// Weighted: critical findings hurt the most, hints barely matter.
func computeHealthScore(findings []analyzer.Finding) HealthScore {
	weights := SeverityWeights()
	byCategory := make(map[string]int)
	penalty := 0
	for _, f := range findings {
		w := weights[f.Severity]
		penalty += w
		byCategory[string(f.Category)] += w
	}

	score := ScoreFromPenalty(penalty)

	grade := "F"
	switch {
	case score >= 90:
		grade = "A"
	case score >= 80:
		grade = "B"
	case score >= 70:
		grade = "C"
	case score >= 60:
		grade = "D"
	case score >= 50:
		grade = "E"
	}

	return HealthScore{
		Score:      score,
		Grade:      grade,
		ByCategory: byCategory,
	}
}

// --- JSON Reporter ---

type jsonReporter struct{}

func (r *jsonReporter) Format() string { return "json" }

func (r *jsonReporter) Write(w io.Writer, report *Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

// --- Text Reporter ---

type textReporter struct{}

func (r *textReporter) Format() string { return "text" }

func (r *textReporter) Write(w io.Writer, report *Report) error {
	writeTextHeader(w, report)
	writeTextFindings(w, report)
	writeTextSummary(w, report)
	return nil
}

func writeTextHeader(w io.Writer, report *Report) {
	fmt.Fprintf(w, "Gollaw v%s — %s\n", report.Version, report.Timestamp)
	fmt.Fprintf(w, "Patterns: %s\n", strings.Join(report.Patterns, ", "))
	fmt.Fprintf(w, "Analyzers: %s\n", strings.Join(report.Analyzers, ", "))
	fmt.Fprintf(w, "Stats: %d packages, %d files, %d functions, %d types\n",
		report.Stats.Packages, report.Stats.Files, report.Stats.Functions, report.Stats.Types)
	fmt.Fprintf(w, "\n")
}

func writeTextFindings(w io.Writer, report *Report) {
	byFile := make(map[string][]analyzer.Finding)
	for _, f := range report.Findings {
		byFile[f.File] = append(byFile[f.File], f)
	}

	files := make([]string, 0, len(byFile))
	for f := range byFile {
		files = append(files, f)
	}
	sort.Strings(files)

	for _, file := range files {
		fmt.Fprintf(w, "▸ %s\n", file)
		fns := byFile[file]
		sort.Slice(fns, func(i, j int) bool { return fns[i].Line < fns[j].Line })
		for _, f := range fns {
			sev := severityIcon(f.Severity)
			fmt.Fprintf(w, "  %s %s:%d  %s\n", sev, shortPath(file), f.Line, f.Message)
			if f.Detail != "" {
				fmt.Fprintf(w, "    %s\n", f.Detail)
			}
			if f.Suggestion != "" {
				fmt.Fprintf(w, "    → %s\n", f.Suggestion)
			}
		}
		fmt.Fprintf(w, "\n")
	}
}

func writeTextSummary(w io.Writer, report *Report) {
	fmt.Fprintf(w, "─── Summary ───\n")
	fmt.Fprintf(w, "Total findings: %d\n", report.Summary.Total)
	for sev, count := range report.Summary.BySeverity {
		fmt.Fprintf(w, "  %s: %d\n", sev, count)
	}
	fmt.Fprintf(w, "\n")
	fmt.Fprintf(w, "Health Score: %d/100 (grade: %s)\n", report.HealthScore.Score, report.HealthScore.Grade)
	if len(report.HealthScore.ByCategory) > 0 {
		writeHealthScoreCategories(w, report.HealthScore.ByCategory)
	}
}

func writeHealthScoreCategories(w io.Writer, byCategory map[string]int) {
	fmt.Fprintf(w, "  by category:\n")
	cats := make([]string, 0, len(byCategory))
	for c := range byCategory {
		cats = append(cats, c)
	}
	sort.Strings(cats)
	for _, c := range cats {
		fmt.Fprintf(w, "    %s: -%d\n", c, byCategory[c])
	}
}

func severityIcon(sev analyzer.Severity) string {
	switch sev {
	case analyzer.SeverityCritical:
		return "🔴"
	case analyzer.SeverityWarning:
		return "🟡"
	case analyzer.SeverityInfo:
		return "🔵"
	case analyzer.SeverityHint:
		return "⚪"
	default:
		return "•"
	}
}

func shortPath(path string) string {
	parts := strings.Split(path, "/")
	if len(parts) <= 3 {
		return path
	}
	return strings.Join(parts[len(parts)-3:], "/")
}

// --- SARIF Reporter ---

type sarifLocation struct {
	PhysicalLocation struct {
		ArtifactLocation struct {
			URI string `json:"uri"`
		} `json:"artifactLocation"`
		Region struct {
			StartLine int `json:"startLine"`
		} `json:"region"`
	} `json:"physicalLocation"`
}

type sarifResult struct {
	RuleID  string `json:"ruleId"`
	Level   string `json:"level"`
	Message struct {
		Text string `json:"text"`
	} `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifRun struct {
	Tool struct {
		Driver struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"driver"`
	} `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifReporter struct{}

func (r *sarifReporter) Format() string { return "sarif" }

func (r *sarifReporter) Write(w io.Writer, report *Report) error {
	results := buildSarifResults(report.Findings)
	sarif := buildSarifReport(report.Version, results)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(sarif)
}

func buildSarifResults(findings []analyzer.Finding) []sarifResult {
	results := make([]sarifResult, len(findings))
	for i, f := range findings {
		loc := sarifLocation{}
		loc.PhysicalLocation.ArtifactLocation.URI = f.File
		loc.PhysicalLocation.Region.StartLine = f.Line
		results[i] = sarifResult{
			RuleID: f.RuleID,
			Level:  sarifLevel(f.Severity),
		}
		results[i].Message.Text = f.Message
		results[i].Locations = []sarifLocation{loc}
	}
	return results
}

func buildSarifReport(version string, results []sarifResult) sarifReport {
	sarif := sarifReport{
		Schema:  "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cs01/schemas/sarif-schema-2.1.0.json",
		Version: "2.1.0",
	}
	sarif.Runs = []sarifRun{{}}
	sarif.Runs[0].Tool.Driver.Name = "gollaw"
	sarif.Runs[0].Tool.Driver.Version = version
	sarif.Runs[0].Results = results
	return sarif
}

func sarifLevel(sev analyzer.Severity) string {
	switch sev {
	case analyzer.SeverityCritical:
		return "error"
	case analyzer.SeverityWarning:
		return "warning"
	default:
		return "note"
	}
}

// --- CodeClimate Reporter ---

type codeClimateReporter struct{}

func (r *codeClimateReporter) Format() string { return "codeclimate" }

func (r *codeClimateReporter) Write(w io.Writer, report *Report) error {
	data, err := formatCodeClimate(report)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

// --- Compact Reporter ---

type compactReporter struct{}

func (r *compactReporter) Format() string { return "compact" }

func (r *compactReporter) Write(w io.Writer, report *Report) error {
	data, err := formatCompact(report)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

// --- Grouped Reporter ---

type groupedReporter struct{}

func (r *groupedReporter) Format() string { return "grouped" }

func (r *groupedReporter) Write(w io.Writer, report *Report) error {
	data, err := formatGrouped(report)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

// --- Markdown Reporter ---

type markdownReporter struct{}

func (r *markdownReporter) Format() string { return "markdown" }

func (r *markdownReporter) Write(w io.Writer, report *Report) error {
	data, err := formatMarkdown(report)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

// --- PR Decision Reporter ---

type prDecisionReporter struct{}

func (r *prDecisionReporter) Format() string { return "pr-decision" }

func (r *prDecisionReporter) Write(w io.Writer, report *Report) error {
	data, err := formatPRDecision(report)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

// --- PR Summary Reporter ---

type prSummaryReporter struct{}

func (r *prSummaryReporter) Format() string { return "pr-summary" }

func (r *prSummaryReporter) Write(w io.Writer, report *Report) error {
	data, err := formatPRSummary(report)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

// --- Impact Reporter ---

type impactReporter struct{}

func (r *impactReporter) Format() string { return "impact" }

func (r *impactReporter) Write(w io.Writer, report *Report) error {
	data, err := formatImpact(report)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

// --- Next Steps Reporter ---

type nextStepsReporter struct{}

func (r *nextStepsReporter) Format() string { return "next-steps" }

func (r *nextStepsReporter) Write(w io.Writer, report *Report) error {
	data, err := formatNextSteps(report)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

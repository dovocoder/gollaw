package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/dovocoder/gollaw/internal/analyzer"
	"github.com/dovocoder/gollaw/internal/loader"
	"github.com/dovocoder/gollaw/internal/reporter"
)

const Version = "0.1.0"

// Run is the main CLI entry point.
func Run(args []string) int {
	if len(args) < 1 {
		printUsage()
		return 1
	}

	switch args[0] {
	case "analyze":
		return runAnalyze(args[1:])
	case "list":
		return runList()
	case "version":
		fmt.Printf("gollaw v%s\n", Version)
		return 0
	case "help", "-h", "--help":
		printUsage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", args[0])
		printUsage()
		return 1
	}
}

func runAnalyze(args []string) int {
	var (
		patterns     []string
		format       = "text"
		analyzerList string
		rules        []string
		minSeverity  = "hint"
		maxCyc       = 0
		maxCog       = 0
		minDup       = 0
		dir          = ""
	)

	// Parse flags and positional patterns.
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--format" || arg == "-f":
			i++
			if i < len(args) {
				format = args[i]
			}
		case strings.HasPrefix(arg, "--format="):
			format = strings.TrimPrefix(arg, "--format=")
		case arg == "--analyzers" || arg == "-a":
			i++
			if i < len(args) {
				analyzerList = args[i]
			}
		case strings.HasPrefix(arg, "--analyzers="):
			analyzerList = strings.TrimPrefix(arg, "--analyzers=")
		case arg == "--rule":
			i++
			if i < len(args) {
				rules = append(rules, args[i])
			}
		case strings.HasPrefix(arg, "--rule="):
			rules = append(rules, strings.TrimPrefix(arg, "--rule="))
		case arg == "--min-severity":
			i++
			if i < len(args) {
				minSeverity = args[i]
			}
		case strings.HasPrefix(arg, "--min-severity="):
			minSeverity = strings.TrimPrefix(arg, "--min-severity=")
		case arg == "--max-cyclomatic":
			i++
			fmt.Sscanf(args[i], "%d", &maxCyc)
		case arg == "--max-cognitive":
			i++
			fmt.Sscanf(args[i], "%d", &maxCog)
		case arg == "--min-dup-lines":
			i++
			fmt.Sscanf(args[i], "%d", &minDup)
		case arg == "--dir":
			i++
			if i < len(args) {
				dir = args[i]
			}
		case strings.HasPrefix(arg, "--dir="):
			dir = strings.TrimPrefix(arg, "--dir=")
		case strings.HasPrefix(arg, "-"):
			fmt.Fprintf(os.Stderr, "unknown flag: %s\n", arg)
			return 1
		default:
			patterns = append(patterns, arg)
		}
	}

	if len(patterns) == 0 {
		patterns = []string{"./..."}
	}

	// Build analyzer config.
	var analyzerNames []string
	if analyzerList != "" {
		analyzerNames = strings.Split(analyzerList, ",")
	}

	var archRules []analyzer.Rule
	for _, r := range rules {
		parts := strings.SplitN(r, " must not import ", 2)
		if len(parts) != 2 {
			fmt.Fprintf(os.Stderr, "invalid rule format (use \"pkg must not import pkg\"): %s\n", r)
			return 1
		}
		archRules = append(archRules, analyzer.Rule{
			Package:    strings.TrimSpace(parts[0]),
			MustNotUse: strings.TrimSpace(parts[1]),
		})
	}

	sev, err := parseSeverity(minSeverity)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}

	aCfg := analyzer.Config{
		Analyzers:     analyzerNames,
		Rules:         archRules,
		MinSeverity:   sev,
		MaxCyclomatic: maxCyc,
		MaxCognitive:  maxCog,
		MinDupLines:   minDup,
	}

	// Load codebase.
	result, err := loader.Load(loader.LoadConfig{
		Patterns: patterns,
		Dir:      dir,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load codebase: %v\n", err)
		return 1
	}

	for _, e := range result.LoadErrors {
		fmt.Fprintf(os.Stderr, "load warning: %v\n", e)
	}

	// Build analyzer context.
	ctx := &analyzer.Context{
		FSET:        result.FSET,
		Packages:    result.Packages,
		SSA:         result.SSA,
		SSAByPkg:    result.SSAByPkg,
		TypesByPkg:  result.TypesByPkg,
		SyntaxByPkg: result.SyntaxByPkg,
		Config:      aCfg,
	}

	// Run analyzers.
	registry := analyzer.NewRegistry()
	selected := registry.Select(analyzerNames)
	if len(selected) == 0 && len(analyzerNames) > 0 {
		fmt.Fprintf(os.Stderr, "no matching analyzers found. Available: %s\n", strings.Join(registry.Names(), ", "))
		return 1
	}

	var allFindings []analyzer.Finding
	ranNames := make([]string, 0, len(selected))
	for _, a := range selected {
		ranNames = append(ranNames, a.Name())
		findings, err := a.Analyze(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "analyzer %s: %v\n", a.Name(), err)
			continue
		}
		allFindings = append(allFindings, findings...)
	}

	// Filter by min severity.
	allFindings = filterBySeverity(allFindings, sev)

	// Build and write report.
	stats := reporter.CodebaseStats{
		Packages:  result.Stats.PackageCount,
		Files:     result.Stats.FileCount,
		Functions: result.Stats.FunctionCount,
		Types:     result.Stats.TypeCount,
		Decls:     result.Stats.DeclCount,
	}

	rep := reporter.BuildReport(Version, patterns, ranNames, stats, allFindings)

	r, err := reporter.NewReporter(format)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}

	if err := r.Write(os.Stdout, rep); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write report: %v\n", err)
		return 1
	}

	// Exit code: 0 = clean, 1 = critical findings, 2 = warnings only.
	if rep.Summary.BySeverity["critical"] > 0 {
		return 1
	}
	return 0
}

func runList() int {
	registry := analyzer.NewRegistry()
	fmt.Println("Available analyzers:")
	for _, a := range registry.All() {
		fmt.Printf("  %-15s  %s\n", a.Name(), a.Description())
	}
	return 0
}

func printUsage() {
	fmt.Println(`Gollaw — whole-codebase intelligence for Go

Usage:
  gollaw analyze [patterns...] [flags]
  gollaw list
  gollaw version
  gollaw help

Commands:
  analyze    Run analyzers on a Go codebase (default: ./...)
  list       List available analyzers
  version    Print version
  help       Show this help

Flags for analyze:
  --format <fmt>          Output format: text, json, sarif (default: text)
  --analyzers <a,b,c>     Comma-separated list of analyzers to run (default: all)
  --rule "<pkg> must not import <pkg>"  Architecture boundary rule (repeatable)
  --min-severity <sev>    Minimum severity: critical, warning, info, hint (default: hint)
  --max-cyclomatic <n>    Max cyclomatic complexity threshold (default: 15)
  --max-cognitive <n>     Max cognitive complexity threshold (default: 20)
  --min-dup-lines <n>     Minimum lines for duplication detection (default: 6)
  --dir <path>            Working directory

Examples:
  gollaw analyze ./...
  gollaw analyze ./... --format json
  gollaw analyze ./internal/... --analyzers deadcode,complexity
  gollaw analyze ./... --rule "internal/store must not import internal/api"`)
}

func parseSeverity(s string) (analyzer.Severity, error) {
	switch strings.ToLower(s) {
	case "critical":
		return analyzer.SeverityCritical, nil
	case "warning":
		return analyzer.SeverityWarning, nil
	case "info":
		return analyzer.SeverityInfo, nil
	case "hint":
		return analyzer.SeverityHint, nil
	default:
		return "", fmt.Errorf("invalid severity: %s (use critical, warning, info, or hint)", s)
	}
}

var severityOrder = map[analyzer.Severity]int{
	analyzer.SeverityCritical: 0,
	analyzer.SeverityWarning:  1,
	analyzer.SeverityInfo:     2,
	analyzer.SeverityHint:     3,
}

func filterBySeverity(findings []analyzer.Finding, min analyzer.Severity) []analyzer.Finding {
	minRank, ok := severityOrder[min]
	if !ok {
		return findings
	}
	var result []analyzer.Finding
	for _, f := range findings {
		rank, ok := severityOrder[f.Severity]
		if !ok || rank <= minRank {
			result = append(result, f)
		}
	}
	return result
}

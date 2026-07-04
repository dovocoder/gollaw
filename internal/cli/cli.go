package cli

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"os"
	"path/filepath"
	"strings"

	"github.com/dovocoder/gollaw/internal/action"
	"github.com/dovocoder/gollaw/internal/audit"
	"github.com/dovocoder/gollaw/internal/analyzer"
	"github.com/dovocoder/gollaw/internal/baseline"
	"github.com/dovocoder/gollaw/internal/codeowners"
	"github.com/dovocoder/gollaw/internal/config"
	"github.com/dovocoder/gollaw/internal/coverage"
	"github.com/dovocoder/gollaw/internal/explain"
	"github.com/dovocoder/gollaw/internal/filescore"
	"github.com/dovocoder/gollaw/internal/guard"
	"github.com/dovocoder/gollaw/internal/lsp"
	"github.com/dovocoder/gollaw/internal/loader"
	"github.com/dovocoder/gollaw/internal/mcp"
	"github.com/dovocoder/gollaw/internal/publicapi"
	"github.com/dovocoder/gollaw/internal/reporter"
	"github.com/dovocoder/gollaw/internal/suppress"
	"github.com/dovocoder/gollaw/internal/trace"
	"github.com/dovocoder/gollaw/internal/watch"
	"github.com/dovocoder/gollaw/internal/xref"
)

const Version = "0.2.0"

// Run is the main CLI entry point.
func Run(args []string) int {
	if len(args) < 1 {
		printUsage()
		return 1
	}

	switch args[0] {
	case "analyze":
		return runAnalyze(args[1:])
	case "audit":
		return runAudit(args[1:])
	case "guard":
		return runGuard(args[1:])
	case "explain":
		return runExplain(args[1:])
	case "trace":
		return runTrace(args[1:])
	case "baseline":
		return runBaseline(args[1:])
	case "health":
		return runHealth(args[1:])
	case "file-scores":
		return runFileScores(args[1:])
	case "xref":
		return runXRef(args[1:])
	case "public-api":
		return runPublicAPI(args[1:])
	case "coverage":
		return runCoverage(args[1:])
	case "owners":
		return runOwners(args[1:])
	case "list":
		return runList()
	case "version":
		fmt.Printf("gollaw v%s\n", Version)
		return 0
	case "lsp":
		return runLSP()
	case "mcp":
		return runMCP()
	case "watch":
		return runWatchCmd(args[1:])
	case "init":
		return runInit(args[1:])
	case "help", "-h", "--help":
		printUsage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", args[0])
		printUsage()
		return 1
	}
}

// ─── shared helpers ───

func loadAndAnalyze(args []string) (*reporter.Report, *analyzer.Context, *loader.Result, int) {
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
		useConfig    = true
		useBaseline  = false
		useSuppress  = true
	)

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
			if i < len(args) {
				fmt.Sscanf(args[i], "%d", &maxCyc)
			}
		case arg == "--max-cognitive":
			i++
			if i < len(args) {
				fmt.Sscanf(args[i], "%d", &maxCog)
			}
		case arg == "--min-dup-lines":
			i++
			if i < len(args) {
				fmt.Sscanf(args[i], "%d", &minDup)
			}
		case arg == "--dir":
			i++
			if i < len(args) {
				dir = args[i]
			}
		case strings.HasPrefix(arg, "--dir="):
			dir = strings.TrimPrefix(arg, "--dir=")
		case arg == "--no-config":
			useConfig = false
		case arg == "--baseline":
			useBaseline = true
		case arg == "--no-suppress":
			useSuppress = false
		case strings.HasPrefix(arg, "-"):
			fmt.Fprintf(os.Stderr, "unknown flag: %s\n", arg)
			return nil, nil, nil, 1
		default:
			patterns = append(patterns, arg)
		}
	}

	if len(patterns) == 0 {
		patterns = []string{"./..."}
	}

	// Load config file if available.
	var fileCfg *config.Config
	if useConfig {
		configPath := config.FindConfig(dir)
		if configPath != "" {
			fc, err := config.Load(configPath)
			if err == nil {
				fileCfg = fc
			}
		}
	}

	var analyzerNames []string
	if analyzerList != "" {
		analyzerNames = strings.Split(analyzerList, ",")
	}

	var archRules []analyzer.Rule
	for _, r := range rules {
		parts := strings.SplitN(r, " must not import ", 2)
		if len(parts) != 2 {
			fmt.Fprintf(os.Stderr, "invalid rule format: %s\n", r)
			return nil, nil, nil, 1
		}
		archRules = append(archRules, analyzer.Rule{
			Package:    strings.TrimSpace(parts[0]),
			MustNotUse: strings.TrimSpace(parts[1]),
		})
	}

	sev, err := parseSeverity(minSeverity)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return nil, nil, nil, 1
	}

	aCfg := analyzer.Config{
		Analyzers:     analyzerNames,
		Rules:         archRules,
		MinSeverity:   sev,
		MaxCyclomatic: maxCyc,
		MaxCognitive:  maxCog,
		MinDupLines:   minDup,
	}

	// Merge with file config (CLI wins).
	if fileCfg != nil {
		aCfg = config.Merge(aCfg, *fileCfg)
	}

	// Load codebase.
	result, err := loader.Load(loader.LoadConfig{
		Patterns: patterns,
		Dir:      dir,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load codebase: %v\n", err)
		return nil, nil, nil, 1
	}

	for _, e := range result.LoadErrors {
		fmt.Fprintf(os.Stderr, "load warning: %v\n", e)
	}

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
	selected := registry.Select(aCfg.Analyzers)
	if len(selected) == 0 && len(aCfg.Analyzers) > 0 {
		fmt.Fprintf(os.Stderr, "no matching analyzers. Available: %s\n", strings.Join(registry.Names(), ", "))
		return nil, nil, nil, 1
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

	// Apply suppressions.
	if useSuppress {
		sup := parseAllSuppressions(ctx)
		if sup != nil {
			allFindings = suppress.FilterSuppressed(allFindings, sup)
		}
	}

	// Filter by min severity.
	allFindings = filterBySeverity(allFindings, sev)

	// Apply baseline diff if requested.
	if useBaseline {
		bl, err := baseline.Load(dir)
		if err == nil && len(bl) > 0 {
			allFindings = baseline.Diff(bl, allFindings)
		}
	}

	stats := reporter.CodebaseStats{
		Packages:  result.Stats.PackageCount,
		Files:     result.Stats.FileCount,
		Functions: result.Stats.FunctionCount,
		Types:     result.Stats.TypeCount,
		Decls:     result.Stats.DeclCount,
	}

	rep := reporter.BuildReport(Version, patterns, ranNames, stats, allFindings)

	// Store format in a way we can access — hack: return via report
	_ = format
	return rep, ctx, result, 0
}

func parseAllSuppressions(ctx *analyzer.Context) *suppress.Suppressions {
	var allFiles []*ast.File
	for _, files := range ctx.SyntaxByPkg {
		allFiles = append(allFiles, files...)
	}
	sup, err := suppress.ParseSuppressions(ctx.FSET, allFiles)
	if err != nil {
		return nil
	}
	return sup
}

// ─── analyze ───

func runAnalyze(args []string) int {
	// Extract format before calling loadAndAnalyze.
	format := "text"
	for i := 0; i < len(args); i++ {
		if args[i] == "--format" || args[i] == "-f" {
			if i+1 < len(args) {
				format = args[i+1]
			}
		} else if strings.HasPrefix(args[i], "--format=") {
			format = strings.TrimPrefix(args[i], "--format=")
		}
	}

	rep, _, _, code := loadAndAnalyze(args)
	if code != 0 {
		return code
	}

	r, err := reporter.NewReporter(format)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}

	if err := r.Write(os.Stdout, rep); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write report: %v\n", err)
		return 1
	}

	if rep.Summary.BySeverity["critical"] > 0 {
		return 1
	}
	return 0
}

// ─── audit ───

func runAudit(args []string) int {
	var (
		baseRef = "origin/main"
		format  = "text"
		dir     = ""
	)

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--base-ref":
			i++
			if i < len(args) {
				baseRef = args[i]
			}
		case "--format", "-f":
			i++
			if i < len(args) {
				format = args[i]
			}
		case "--dir":
			i++
			if i < len(args) {
				dir = args[i]
			}
		}
	}

	rep, ctx, _, code := loadAndAnalyze([]string{"--dir", dir, "--no-config"})
	if code != 0 {
		return code
	}

	auditRep, err := audit.RunAudit(ctx, baseRef, rep.Findings, dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "audit error: %v\n", err)
		return 1
	}

	switch format {
	case "json":
		data, _ := audit.FormatAuditJSON(auditRep)
		fmt.Println(string(data))
	case "markdown":
		fmt.Println(action.FormatPRComment(auditRep))
	default:
		fmt.Print(audit.FormatAuditText(auditRep))
	}

	if auditRep.Verdict == "fail" {
		return 1
	}
	return 0
}

// ─── guard ───

func runGuard(args []string) int {
	var (
		filePath string
		format   = "text"
		dir      = ""
		rules    []string
	)

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--format", "-f":
			i++
			if i < len(args) {
				format = args[i]
			}
		case "--dir":
			i++
			if i < len(args) {
				dir = args[i]
			}
		case "--rule":
			i++
			if i < len(args) {
				rules = append(rules, args[i])
			}
		default:
			if !strings.HasPrefix(args[i], "-") {
				filePath = args[i]
			}
		}
	}

	if filePath == "" {
		fmt.Fprintln(os.Stderr, "usage: gollaw guard <file.go> [--rule ...]")
		return 1
	}

	// Load config for rules.
	var archRules []analyzer.Rule
	for _, r := range rules {
		parts := strings.SplitN(r, " must not import ", 2)
		if len(parts) == 2 {
			archRules = append(archRules, analyzer.Rule{
				Package:    strings.TrimSpace(parts[0]),
				MustNotUse: strings.TrimSpace(parts[1]),
			})
		}
	}

	// Load config file rules if available.
	configPath := config.FindConfig(dir)
	if configPath != "" {
		fc, err := config.Load(configPath)
		if err == nil && len(fc.Rules) > 0 && len(archRules) == 0 {
			// Parse string rules into analyzer.Rule structs.
			for _, r := range fc.Rules {
				parts := strings.SplitN(r, " must not import ", 2)
				if len(parts) == 2 {
					archRules = append(archRules, analyzer.Rule{
						Package:    strings.TrimSpace(parts[0]),
						MustNotUse: strings.TrimSpace(parts[1]),
					})
				}
			}
		}
	}

	// Load codebase.
	result, err := loader.Load(loader.LoadConfig{
		Patterns: []string{"./..."},
		Dir:      dir,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load: %v\n", err)
		return 1
	}

	ctx := &analyzer.Context{
		FSET:        result.FSET,
		Packages:    result.Packages,
		SSA:         result.SSA,
		SSAByPkg:    result.SSAByPkg,
		TypesByPkg:  result.TypesByPkg,
		SyntaxByPkg: result.SyntaxByPkg,
		Config:      analyzer.Config{Rules: archRules},
	}

	absPath, _ := filepath.Abs(filePath)
	guardRep, err := guard.BuildGuardReport(ctx, archRules, absPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "guard error: %v\n", err)
		return 1
	}

	switch format {
	case "json":
		data, _ := guard.FormatGuardJSON(guardRep)
		fmt.Println(string(data))
	default:
		fmt.Print(guard.FormatGuardText(guardRep))
	}
	return 0
}

// ─── explain ───

func runExplain(args []string) int {
	var (
		symbol string
		format = "text"
		dir    = ""
	)

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--format", "-f":
			i++
			if i < len(args) {
				format = args[i]
			}
		case "--dir":
			i++
			if i < len(args) {
				dir = args[i]
			}
		default:
			if !strings.HasPrefix(args[i], "-") {
				symbol = args[i]
			}
		}
	}

	if symbol == "" {
		fmt.Fprintln(os.Stderr, "usage: gollaw explain <symbol>")
		return 1
	}

	result, err := loader.Load(loader.LoadConfig{Patterns: []string{"./..."}, Dir: dir})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load: %v\n", err)
		return 1
	}

	ctx := &analyzer.Context{
		FSET: result.FSET, Packages: result.Packages, SSA: result.SSA,
		SSAByPkg: result.SSAByPkg, TypesByPkg: result.TypesByPkg, SyntaxByPkg: result.SyntaxByPkg,
	}

	var exp *explain.Explanation
	exp, err = explain.ExplainUnused(ctx, symbol)
	if err != nil || exp == nil {
		exp, err = explain.ExplainDead(ctx, symbol)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "explain error: %v\n", err)
		return 1
	}
	if exp == nil {
		fmt.Printf("symbol %q not found\n", symbol)
		return 1
	}

	switch format {
	case "json":
		data, _ := explain.FormatExplanationJSON(exp)
		fmt.Println(string(data))
	default:
		fmt.Print(explain.FormatExplanation(exp))
	}
	return 0
}

// ─── trace ───

func runTrace(args []string) int {
	var (
		symbol    string
		direction = "callers"
		format    = "text"
		dir       = ""
		maxDepth  = 10
	)

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--direction":
			i++
			if i < len(args) {
				direction = args[i]
			}
		case "--format", "-f":
			i++
			if i < len(args) {
				format = args[i]
			}
		case "--dir":
			i++
			if i < len(args) {
				dir = args[i]
			}
		case "--max-depth":
			i++
			if i < len(args) {
				fmt.Sscanf(args[i], "%d", &maxDepth)
			}
		default:
			if !strings.HasPrefix(args[i], "-") {
				symbol = args[i]
			}
		}
	}

	if symbol == "" {
		fmt.Fprintln(os.Stderr, "usage: gollaw trace <symbol> [--direction callers|callees]")
		return 1
	}

	result, err := loader.Load(loader.LoadConfig{Patterns: []string{"./..."}, Dir: dir})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load: %v\n", err)
		return 1
	}

	ctx := &analyzer.Context{
		FSET: result.FSET, Packages: result.Packages, SSA: result.SSA,
		SSAByPkg: result.SSAByPkg, TypesByPkg: result.TypesByPkg, SyntaxByPkg: result.SyntaxByPkg,
	}

	var tr *trace.TraceResult
	if direction == "callees" {
		tr, err = trace.TraceCallees(ctx, symbol, maxDepth)
	} else {
		tr, err = trace.TraceCallers(ctx, symbol, maxDepth)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "trace error: %v\n", err)
		return 1
	}
	if tr == nil {
		fmt.Printf("symbol %q not found\n", symbol)
		return 1
	}

	switch format {
	case "json":
		data, _ := trace.FormatTraceJSON(tr)
		fmt.Println(string(data))
	default:
		fmt.Print(trace.FormatTraceText(tr))
	}
	return 0
}

// ─── baseline ───

func runBaseline(args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: gollaw baseline <save|diff|show>")
		return 1
	}

	dir := ""
	for i := 1; i < len(args); i++ {
		if args[i] == "--dir" && i+1 < len(args) {
			dir = args[i+1]
			i++
		}
	}

	switch args[0] {
	case "save":
		rep, _, _, code := loadAndAnalyze([]string{"--dir", dir, "--no-config"})
		if code != 0 {
			return code
		}
		if err := baseline.Save(dir, rep.Findings); err != nil {
			fmt.Fprintf(os.Stderr, "save baseline: %v\n", err)
			return 1
		}
		fmt.Printf("baseline saved: %d findings\n", len(rep.Findings))
		return 0

	case "diff":
		rep, _, _, code := loadAndAnalyze([]string{"--dir", dir, "--no-config"})
		if code != 0 {
			return code
		}
		bl, err := baseline.Load(dir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "load baseline: %v\n", err)
			return 1
		}
		newFindings := baseline.Diff(bl, rep.Findings)
		fmt.Printf("New findings since baseline: %d\n", len(newFindings))
		for _, f := range newFindings {
			fmt.Printf("  %s %s:%d %s\n", f.Severity, f.File, f.Line, f.Message)
		}
		return 0

	case "show":
		bl, err := baseline.Load(dir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "load baseline: %v\n", err)
			return 1
		}
		fmt.Printf("Baseline: %d findings\n", len(bl))
		for _, f := range bl {
			fmt.Printf("  %s %s:%d %s\n", f.Severity, f.File, f.Line, f.Message)
		}
		return 0

	default:
		fmt.Fprintf(os.Stderr, "unknown baseline command: %s\n", args[0])
		return 1
	}
}

// ─── health ───

func runHealth(args []string) int {
	format := "text"
	dir := ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--format", "-f":
			i++
			if i < len(args) {
				format = args[i]
			}
		case "--dir":
			i++
			if i < len(args) {
				dir = args[i]
			}
		}
	}

	rep, _, _, code := loadAndAnalyze([]string{"--dir", dir, "--no-config"})
	if code != 0 {
		return code
	}

	switch format {
	case "json":
		data, _ := json.MarshalIndent(rep.HealthScore, "", "  ")
		fmt.Println(string(data))
	default:
		fmt.Printf("Health Score: %d/100 (grade: %s)\n", rep.HealthScore.Score, rep.HealthScore.Grade)
		if len(rep.HealthScore.ByCategory) > 0 {
			fmt.Println("  by category:")
			for cat, penalty := range rep.HealthScore.ByCategory {
				fmt.Printf("    %s: -%d\n", cat, penalty)
			}
		}
	}
	return 0
}

// ─── file-scores ───

func runFileScores(args []string) int {
	format := "text"
	dir := ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--format", "-f":
			i++
			if i < len(args) {
				format = args[i]
			}
		case "--dir":
			i++
			if i < len(args) {
				dir = args[i]
			}
		}
	}

	rep, _, _, code := loadAndAnalyze([]string{"--dir", dir, "--no-config"})
	if code != 0 {
		return code
	}

	scores := filescore.ScoreFiles(rep.Findings, nil)
	switch format {
	case "json":
		data, _ := filescore.FormatFileScoresJSON(scores)
		fmt.Println(string(data))
	default:
		fmt.Print(filescore.FormatFileScoresText(scores))
	}
	return 0
}

// ─── xref ───

func runXRef(args []string) int {
	format := "text"
	dir := ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--format", "-f":
			i++
			if i < len(args) {
				format = args[i]
			}
		case "--dir":
			i++
			if i < len(args) {
				dir = args[i]
			}
		}
	}

	rep, _, _, code := loadAndAnalyze([]string{"--dir", dir, "--no-config"})
	if code != 0 {
		return code
	}

	combined := xref.CrossReference(rep.Findings)
	switch format {
	case "json":
		data, _ := xref.FormatXRefJSON(combined)
		fmt.Println(string(data))
	default:
		fmt.Print(xref.FormatXRefText(combined))
	}
	return 0
}

// ─── public-api ───

func runPublicAPI(args []string) int {
	format := "text"
	dir := ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--format", "-f":
			i++
			if i < len(args) {
				format = args[i]
			}
		case "--dir":
			i++
			if i < len(args) {
				dir = args[i]
			}
		}
	}

	result, err := loader.Load(loader.LoadConfig{Patterns: []string{"./..."}, Dir: dir})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load: %v\n", err)
		return 1
	}

	ctx := &analyzer.Context{
		FSET: result.FSET, Packages: result.Packages, SSA: result.SSA,
		SSAByPkg: result.SSAByPkg, TypesByPkg: result.TypesByPkg, SyntaxByPkg: result.SyntaxByPkg,
	}

	apiRep, err := publicapi.AnalyzePublicAPI(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "public-api error: %v\n", err)
		return 1
	}

	switch format {
	case "json":
		data, _ := publicapi.FormatPublicAPIJSON(apiRep)
		fmt.Println(string(data))
	default:
		fmt.Print(publicapi.FormatPublicAPIText(apiRep))
	}
	return 0
}

// ─── coverage ───

func runCoverage(args []string) int {
	format := "text"
	dir := ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--format", "-f":
			i++
			if i < len(args) {
				format = args[i]
			}
		case "--dir":
			i++
			if i < len(args) {
				dir = args[i]
			}
		}
	}

	result, err := loader.Load(loader.LoadConfig{Patterns: []string{"./..."}, Dir: dir})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load: %v\n", err)
		return 1
	}

	ctx := &analyzer.Context{
		FSET: result.FSET, Packages: result.Packages, SSA: result.SSA,
		SSAByPkg: result.SSAByPkg, TypesByPkg: result.TypesByPkg, SyntaxByPkg: result.SyntaxByPkg,
	}

	covRep, err := coverage.AnalyzeCoverage(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "coverage error: %v\n", err)
		return 1
	}

	switch format {
	case "json":
		data, _ := coverage.FormatCoverageJSON(covRep)
		fmt.Println(string(data))
	default:
		fmt.Print(coverage.FormatCoverageText(covRep))
	}
	return 0
}

// ─── owners ───

func runOwners(args []string) int {
	format := "text"
	dir := ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--format", "-f":
			i++
			if i < len(args) {
				format = args[i]
			}
		case "--dir":
			i++
			if i < len(args) {
				dir = args[i]
			}
		}
	}

	rep, _, _, code := loadAndAnalyze([]string{"--dir", dir, "--no-config"})
	if code != 0 {
		return code
	}

	ownersFile, err := codeowners.FindCodeOwnersFile(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "no CODEOWNERS file found: %v\n", err)
		return 1
	}

	owners, err := codeowners.Parse(ownersFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse CODEOWNERS: %v\n", err)
		return 1
	}

	groups := codeowners.GroupByOwner(rep.Findings, owners)
	switch format {
	case "json":
		data, _ := codeowners.FormatOwnershipJSON(groups)
		fmt.Println(string(data))
	default:
		fmt.Print(codeowners.FormatOwnershipText(groups))
	}
	return 0
}

// ─── LSP ───

func runLSP() int {
	if err := lsp.ServeLSP(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "LSP error: %v\n", err)
		return 1
	}
	return 0
}

// ─── MCP ───

func runMCP() int {
	if err := mcp.ServeMCP(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "MCP error: %v\n", err)
		return 1
	}
	return 0
}

// ─── watch ───

func runWatchCmd(args []string) int {
	dir := "."
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--dir":
			i++
			if i < len(args) {
				dir = args[i]
			}
		}
	}

	fmt.Printf("Watching %s for changes...\n", dir)
	onChange := func() {
		fmt.Println("Change detected — re-running analysis...")
		rep, _, _, code := loadAndAnalyze([]string{"--dir", dir})
		if code != 0 {
			fmt.Fprintf(os.Stderr, "analysis failed\n")
			return
		}
		r, _ := reporter.NewReporter("text")
		r.Write(os.Stdout, rep)
	}

	if err := watch.Watch(dir, []string{"./..."}, onChange); err != nil {
		fmt.Fprintf(os.Stderr, "watch error: %v\n", err)
		return 1
	}
	return 0
}

// ─── init ───

func runInit(args []string) int {
	dir := "."
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		dir = args[0]
	}

	// Create directory if it doesn't exist.
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "create dir: %v\n", err)
			return 1
		}
	}

	configPath := filepath.Join(dir, ".gollaw.yaml")
	if _, err := os.Stat(configPath); err == nil {
		fmt.Printf(".gollaw.yaml already exists at %s\n", configPath)
		return 1
	}

	defaultConfig := `# Gollaw configuration
analyzers:
  enabled: []  # empty = all analyzers
  disabled: []

thresholds:
  max-cyclomatic: 15
  max-cognitive: 20
  max-function-lines: 50
  min-dup-lines: 6

rules: []
  # - "internal/store must not import internal/api"
  # - "internal/cli must not import internal/analyzer"

ignore:
  - "vendor/**"
  - "**/*_test.go"
  - "**/testdata/**"

severity:
  min: hint  # critical, warning, info, hint
`

	if err := os.WriteFile(configPath, []byte(defaultConfig), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "write config: %v\n", err)
		return 1
	}
	fmt.Printf("Created .gollaw.yaml at %s\n", configPath)
	return 0
}

// ─── list ───

func runList() int {
	registry := analyzer.NewRegistry()
	fmt.Println("Available analyzers:")
	for _, a := range registry.All() {
		fmt.Printf("  %-15s  %s\n", a.Name(), a.Description())
	}
	return 0
}

// ─── usage ───

func printUsage() {
	fmt.Println(`Gollaw — whole-codebase intelligence for Go

Usage:
  gollaw <command> [flags] [args]

Commands:
  analyze [patterns]    Run analyzers on a Go codebase (default: ./...)
  audit                 PR audit: analyze changed files vs base ref
  guard <file>          Pre-edit architecture guidance for a file
  explain <symbol>      Explain why a symbol is unused/dead
  trace <symbol>        Trace callers/callees of a symbol
  baseline <save|diff>  Save or diff against a findings baseline
  health                Get project health score
  file-scores           Per-file health scores
  xref                  Cross-reference findings (e.g. duplicate + dead)
  public-api            Analyze public API surface
  coverage              Test coverage gap analysis
  owners                Group findings by CODEOWNERS
  init                  Create .gollaw.yaml config file
  list                  List available analyzers
  version               Print version
  lsp                   Start LSP server (for editor integration)
  mcp                   Start MCP server (for AI agent integration)
  watch                 Watch for file changes and re-analyze
  help                  Show this help

Common flags:
  --format <fmt>        Output: text, json, sarif, markdown (default: text)
  --analyzers <a,b,c>   Comma-separated analyzer names (default: all)
  --rule "A must not import B"  Architecture boundary rule (repeatable)
  --min-severity <sev>  critical, warning, info, hint (default: hint)
  --dir <path>          Working directory
  --no-config           Skip .gollaw.yaml
  --baseline            Only show new findings since baseline
  --no-suppress         Ignore //gollaw:keep suppression comments

Examples:
  gollaw analyze ./...
  gollaw analyze ./... --format json --analyzers deadcode,complexity
  gollaw audit --base-ref origin/main --format markdown
  gollaw guard internal/store/user.go
  gollaw explain MyFunction
  gollaw trace MyFunction --direction callers
  gollaw baseline save
  gollaw baseline diff
  gollaw health --format json
  gollaw coverage
  gollaw public-api
  gollaw lsp  # for editor integration
  gollaw mcp  # for AI agent integration`)
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

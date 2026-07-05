// Package cli implements the command-line interface for Gollaw.
//
//gollaw:ignore dependencies
package cli

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"os"
	"path/filepath"
	"strings"

	"github.com/dovocoder/gollaw/internal/action"
	"github.com/dovocoder/gollaw/internal/analyzer"
	"github.com/dovocoder/gollaw/internal/audit"
	"github.com/dovocoder/gollaw/internal/baseline"
	"github.com/dovocoder/gollaw/internal/codeowners"
	"github.com/dovocoder/gollaw/internal/config"
	"github.com/dovocoder/gollaw/internal/coverage"
	"github.com/dovocoder/gollaw/internal/explain"
	"github.com/dovocoder/gollaw/internal/filescore"
	"github.com/dovocoder/gollaw/internal/fix"
	"github.com/dovocoder/gollaw/internal/graph"
	"github.com/dovocoder/gollaw/internal/guard"
	"github.com/dovocoder/gollaw/internal/health"
	"github.com/dovocoder/gollaw/internal/inspect"
	"github.com/dovocoder/gollaw/internal/loader"
	"github.com/dovocoder/gollaw/internal/lsp"
	"github.com/dovocoder/gollaw/internal/mcp"
	"github.com/dovocoder/gollaw/internal/migrate"
	"github.com/dovocoder/gollaw/internal/publicapi"
	"github.com/dovocoder/gollaw/internal/regression"
	"github.com/dovocoder/gollaw/internal/reporter"
	"github.com/dovocoder/gollaw/internal/rulepack"
	"github.com/dovocoder/gollaw/internal/suppress"
	"github.com/dovocoder/gollaw/internal/trace"
	"github.com/dovocoder/gollaw/internal/walkthrough"
	"github.com/dovocoder/gollaw/internal/watch"
	"github.com/dovocoder/gollaw/internal/xref"
)

// Version is set at build time via -ldflags "-X github.com/dovocoder/gollaw/internal/cli.Version=v0.2.0".
//
//gollaw:ignore api-surface
var Version = "0.2.0-dev"

// Run is the main CLI entry point.
func Run(args []string) int {
	if len(args) < 1 {
		fmt.Println(usageText)
		return 1
	}
	return dispatchCommand(args[0], args[1:])
}

// dispatchCommand routes to the appropriate command handler.
func dispatchCommand(cmd string, rest []string) int {
	if code, ok := tryAnalysisCommand(cmd, rest); ok {
		return code
	}
	if code, ok := tryReportCommand(cmd, rest); ok {
		return code
	}
	if code, ok := tryUtilityCommand(cmd, rest); ok {
		return code
	}
	switch cmd {
	case "help", "-h", "--help":
		fmt.Println(usageText)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		fmt.Println(usageText)
		return 1
	}
}

// tryAnalysisCommand handles analysis-related commands.
func tryAnalysisCommand(cmd string, rest []string) (int, bool) {
	switch cmd {
	case "analyze":
		return runAnalyze(rest), true
	case "audit":
		return runAudit(rest), true
	case "guard":
		return runGuard(rest), true
	case "explain":
		return runExplain(rest), true
	case "trace":
		return runTrace(rest), true
	case "baseline":
		return runBaseline(rest), true
	case "fix":
		return runFix(rest), true
	case "inspect":
		return runInspect(rest), true
	case "regression":
		return runRegression(rest), true
	}
	return 0, false
}

// tryReportCommand handles report-generating commands.
func tryReportCommand(cmd string, rest []string) (int, bool) {
	switch cmd {
	case "health":
		return runHealth(rest), true
	case "file-scores":
		return runFileScores(rest), true
	case "xref":
		return runXRef(rest), true
	case "public-api":
		return runPublicAPI(rest), true
	case "coverage":
		return runCoverage(rest), true
	case "owners":
		return runOwners(rest), true
	case "impact":
		return runImpact(rest), true
	case "vital-signs":
		return runVitalSigns(rest), true
	case "targets":
		return runTargets(rest), true
	case "trends":
		return runTrends(rest), true
	case "timings":
		return runTimings(rest), true
	case "walkthrough":
		return runWalkthrough(rest), true
	}
	return 0, false
}

// tryUtilityCommand handles utility commands.
func tryUtilityCommand(cmd string, rest []string) (int, bool) {
	switch cmd {
	case "list":
		return runList(), true
	case "version":
		fmt.Printf("gollaw v%s\n", Version)
		return 0, true
	case "lsp":
		return runLSP(), true
	case "mcp":
		return runMCP(), true
	case "watch":
		return runWatchCmd(rest), true
	case "init":
		return runInit(rest), true
	case "migrate":
		return runMigrate(rest), true
	case "rule-pack":
		return runRulePack(rest), true
	}
	return 0, false
}

// ─── shared helpers ───

type analyzeOpts struct {
	patterns     []string
	format       string
	analyzerList string
	rules        []string
	minSeverity  string
	maxCyc       int
	maxCog       int
	minDup       int
	dir          string
	useConfig    bool
	useBaseline  bool
	useSuppress  bool
}

func parseAnalyzeFlags(args []string) (analyzeOpts, int) {
	o := analyzeOpts{
		format:      "text",
		minSeverity: "hint",
		useConfig:   true,
		useSuppress: true,
	}
	if code := o.parseFlags(args); code != 0 {
		return o, code
	}
	o.finalizePatterns()
	return o, 0
}

// parseFlags processes command-line flags into the analyzeOpts.
func (o *analyzeOpts) parseFlags(args []string) int {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		handled, err := o.parseOneFlag(args, &i, arg)
		if err {
			return 1
		}
		if !handled {
			o.patterns = append(o.patterns, arg)
		}
	}
	return 0
}

// parseOneFlag parses a single flag argument. Returns (handled, hadError).
func (o *analyzeOpts) parseOneFlag(args []string, i *int, arg string) (bool, bool) {
	if val, ok := parseFlagValue(args, i, "--format", "-f"); ok {
		o.format = val
		return true, false
	}
	if val, ok := parseFlagEquals(arg, "--format="); ok {
		o.format = val
		return true, false
	}
	if val, ok := o.parseStringFlag(args, i, arg); val != "" || ok {
		return true, false
	}
	if ok := o.parseNumericFlag(args, i, arg); ok {
		return true, false
	}
	if ok := o.parseBoolFlag(arg); ok {
		return true, false
	}
	if strings.HasPrefix(arg, "-") {
		fmt.Fprintf(os.Stderr, "unknown flag: %s\n", arg)
		return true, true
	}
	return false, false
}

// parseStringFlag handles string-valued flags.
func (o *analyzeOpts) parseStringFlag(args []string, i *int, arg string) (string, bool) {
	// Check -a shorthand first
	if val, ok := parseFlagValue(args, i, "-a"); ok {
		o.analyzerList = val
		return val, true
	}
	flags := []struct{ sep, long string }{
		{"--analyzers=", "--analyzers"},
		{"--rule=", "--rule"},
		{"--min-severity=", "--min-severity"},
		{"--dir=", "--dir"},
	}
	for _, f := range flags {
		// Check --flag value (space-separated)
		if val, ok := parseFlagValue(args, i, f.long); ok {
			o.assignString(f.long, val)
			return val, true
		}
		// Check --flag=value (equals-separated)
		if val, ok := parseFlagEquals(arg, f.sep); ok {
			o.assignString(f.long, val)
			return val, true
		}
	}
	return "", false
}

// assignString sets the appropriate string field based on flag name.
func (o *analyzeOpts) assignString(flag, val string) {
	switch flag {
	case "--analyzers":
		o.analyzerList = val
	case "--rule":
		o.rules = append(o.rules, val)
	case "--min-severity":
		o.minSeverity = val
	case "--dir":
		o.dir = val
	}
}

// parseNumericFlag handles numeric flags.
func (o *analyzeOpts) parseNumericFlag(args []string, i *int, arg string) bool {
	numericFlags := []struct {
		name string
		dst  *int
	}{
		{"--max-cyclomatic", &o.maxCyc},
		{"--max-cognitive", &o.maxCog},
		{"--min-dup-lines", &o.minDup},
	}
	for _, f := range numericFlags {
		if val, ok := parseFlagValue(args, i, f.name); ok {
			fmt.Sscanf(val, "%d", f.dst)
			return true
		}
	}
	return false
}

// parseBoolFlag handles boolean flags.
func (o *analyzeOpts) parseBoolFlag(arg string) bool {
	switch arg {
	case "--no-config":
		o.useConfig = false
		return true
	case "--baseline":
		o.useBaseline = true
		return true
	case "--no-suppress":
		o.useSuppress = false
		return true
	}
	return false
}

// finalizePatterns sets default patterns and expands "." to "./...".
func (o *analyzeOpts) finalizePatterns() {
	if len(o.patterns) == 0 {
		o.patterns = []string{"./..."}
	}
	for i, p := range o.patterns {
		if p == "." {
			o.patterns[i] = "./..."
		}
	}
}

// parseFlagValue extracts a value for a flag that takes a separate argument.
// Returns (value, true) if the flag matched, ("", false) otherwise.
func parseFlagValue(args []string, i *int, names ...string) (string, bool) {
	for _, name := range names {
		if args[*i] == name {
			if *i+1 < len(args) {
				*i++
				return args[*i], true
			}
			return "", true
		}
	}
	return "", false
}

// parseFlagEquals extracts a value from a --flag=value style argument.
func parseFlagEquals(arg, prefix string) (string, bool) {
	if strings.HasPrefix(arg, prefix) {
		return strings.TrimPrefix(arg, prefix), true
	}
	return "", false
}

// assignNextString advances i and assigns the following arg to dst if present.
func assignNextString(args []string, i *int, dst *string) {
	*i++
	if *i < len(args) {
		*dst = args[*i]
	}
}

func buildAnalyzerConfig(o analyzeOpts) (analyzer.Config, int) {
	var analyzerNames []string
	if o.analyzerList != "" {
		analyzerNames = strings.Split(o.analyzerList, ",")
	}
	var archRules []analyzer.Rule
	for _, r := range o.rules {
		parts := strings.SplitN(r, " must not import ", 2)
		if len(parts) != 2 {
			fmt.Fprintf(os.Stderr, "invalid rule format: %s\n", r)
			return analyzer.Config{}, 1
		}
		archRules = append(archRules, analyzer.Rule{
			Package:    strings.TrimSpace(parts[0]),
			MustNotUse: strings.TrimSpace(parts[1]),
		})
	}
	sev, err := parseSeverity(o.minSeverity)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return analyzer.Config{}, 1
	}
	aCfg := analyzer.Config{
		Analyzers:     analyzerNames,
		Rules:         archRules,
		MinSeverity:   sev,
		MaxCyclomatic: o.maxCyc,
		MaxCognitive:  o.maxCog,
		MinDupLines:   o.minDup,
	}
	if o.useConfig {
		configPath := config.FindConfig(o.dir)
		if configPath != "" {
			if fc, err := config.Load(configPath); err == nil {
				aCfg = config.Merge(aCfg, *fc)
			}
		}
	}
	return aCfg, 0
}

func runAnalyzers(ctx *analyzer.Context, aCfg analyzer.Config, useSuppress bool, useBaseline bool, dir string) ([]analyzer.Finding, []string) {
	registry := analyzer.NewRegistry()
	selected := registry.Select(aCfg.Analyzers)
	if len(selected) == 0 && len(aCfg.Analyzers) > 0 {
		fmt.Fprintf(os.Stderr, "no matching analyzers. Available: %s\n", strings.Join(registry.Names(), ", "))
		return nil, nil
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
	if useSuppress {
		sup := parseAllSuppressions(ctx)
		if sup != nil {
			allFindings = suppress.FilterSuppressed(allFindings, sup)
		}
	}
	allFindings = filterBySeverity(allFindings, aCfg.MinSeverity)
	if useBaseline {
		bl, err := baseline.Load(dir)
		if err == nil && len(bl) > 0 {
			allFindings = baseline.Diff(bl, allFindings)
		}
	}
	return allFindings, ranNames
}

func loadAndAnalyze(args []string) (*reporter.Report, *analyzer.Context, *loader.Result, int) {
	o, code := parseAnalyzeFlags(args)
	if code != 0 {
		return nil, nil, nil, code
	}
	aCfg, code := buildAnalyzerConfig(o)
	if code != 0 {
		return nil, nil, nil, code
	}
	result, err := loader.Load(loader.LoadConfig{
		Patterns: o.patterns,
		Dir:      o.dir,
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
	allFindings, ranNames := runAnalyzers(ctx, aCfg, o.useSuppress, o.useBaseline, o.dir)
	stats := reporter.CodebaseStats{
		Packages:  result.Stats.PackageCount,
		Files:     result.Stats.FileCount,
		Functions: result.Stats.FunctionCount,
		Types:     result.Stats.TypeCount,
		Decls:     result.Stats.DeclCount,
	}
	rep := reporter.BuildReport(Version, o.patterns, ranNames, stats, allFindings)
	_ = o.format
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

// ─── shared command helpers ───

// formatDirOpts holds parsed --format and --dir flags.
type formatDirOpts struct {
	format string
	dir    string
}

// parseFormatDir parses --format/-f and --dir flags from args.
func parseFormatDir(args []string) formatDirOpts {
	o := formatDirOpts{format: "text", dir: "."}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--format", "-f":
			i++
			if i < len(args) {
				o.format = args[i]
			}
		case "--dir":
			i++
			if i < len(args) {
				o.dir = args[i]
			}
		}
	}
	return o
}

// loadSimple loads the codebase and returns the analysis context.
// It uses ./... as pattern with --no-config.
func loadSimple(dir string) (*reporter.Report, *analyzer.Context, int) {
	rep, ctx, _, code := loadAndAnalyze([]string{"--dir", dir, "--no-config"})
	return rep, ctx, code
}

// loadResult loads the codebase with loader.Load and returns the context.
func loadResult(dir string) (*analyzer.Context, *loader.Result, int) {
	result, err := loader.Load(loader.LoadConfig{Patterns: []string{"./..."}, Dir: dir})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load: %v\n", err)
		return nil, nil, 1
	}
	ctx := &analyzer.Context{
		FSET: result.FSET, Packages: result.Packages, SSA: result.SSA,
		SSAByPkg: result.SSAByPkg, TypesByPkg: result.TypesByPkg, SyntaxByPkg: result.SyntaxByPkg,
	}
	return ctx, result, 0
}

// loadAndScore loads the codebase (via loadSimple) and computes per-file scores.
func loadAndScore(dir string) (*reporter.Report, []filescore.FileHealthScore, int) {
	rep, _, code := loadSimple(dir)
	if code != 0 {
		return nil, nil, code
	}
	scores := filescore.ScoreFiles(rep.Findings, nil)
	return rep, scores, 0
}

// printJSONOrText prints data as JSON or text based on format.
func printJSONOrText(format string, jsonFn func() ([]byte, error), textFn func() string) {
	switch format {
	case "json":
		data, _ := jsonFn()
		fmt.Println(string(data))
	default:
		fmt.Print(textFn())
	}
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

// auditOpts holds parsed audit command flags.
type auditOpts struct {
	baseRef string
	format  string
	dir     string
}

// parseAuditFlags parses audit command-line flags.
func parseAuditFlags(args []string) auditOpts {
	o := auditOpts{baseRef: "origin/main", format: "text", dir: ""}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--base-ref":
			i++
			if i < len(args) {
				o.baseRef = args[i]
			}
		case "--format", "-f":
			i++
			if i < len(args) {
				o.format = args[i]
			}
		case "--dir":
			i++
			if i < len(args) {
				o.dir = args[i]
			}
		}
	}
	return o
}

func runAudit(args []string) int {
	o := parseAuditFlags(args)
	rep, ctx, _, code := loadAndAnalyze([]string{"--dir", o.dir, "--no-config"})
	if code != 0 {
		return code
	}
	auditRep, err := audit.RunAudit(ctx, o.baseRef, rep.Findings, o.dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "audit error: %v\n", err)
		return 1
	}
	switch o.format {
	case "json":
		data, _ := json.MarshalIndent(auditRep, "", "  ")
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

// guardOpts holds parsed guard command flags.
type guardOpts struct {
	filePath string
	format   string
	dir      string
	rules    []string
}

// parseGuardFlags parses guard command-line flags.
func parseGuardFlags(args []string) guardOpts {
	o := guardOpts{format: "text", dir: ""}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--format", "-f":
			i++
			if i < len(args) {
				o.format = args[i]
			}
		case "--dir":
			i++
			if i < len(args) {
				o.dir = args[i]
			}
		case "--rule":
			i++
			if i < len(args) {
				o.rules = append(o.rules, args[i])
			}
		default:
			if !strings.HasPrefix(args[i], "-") {
				o.filePath = args[i]
			}
		}
	}
	return o
}

// parseArchRules parses "A must not import B" rule strings into analyzer.Rule structs.
func parseArchRules(rules []string) []analyzer.Rule {
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
	return archRules
}

// loadGuardRules collects architecture rules from CLI flags and config file.
func loadGuardRules(o guardOpts) []analyzer.Rule {
	archRules := parseArchRules(o.rules)
	configPath := config.FindConfig(o.dir)
	if configPath == "" {
		return archRules
	}
	fc, err := config.Load(configPath)
	if err != nil || len(fc.Rules) == 0 || len(archRules) > 0 {
		return archRules
	}
	return append(archRules, parseArchRules(fc.Rules)...)
}

func runGuard(args []string) int {
	o := parseGuardFlags(args)
	if o.filePath == "" {
		fmt.Fprintln(os.Stderr, "usage: gollaw guard <file.go> [--rule ...]")
		return 1
	}
	archRules := loadGuardRules(o)
	ctx, _, code := loadResult(o.dir)
	if code != 0 {
		return code
	}
	ctx.Config = analyzer.Config{Rules: archRules}
	absPath, _ := filepath.Abs(o.filePath)
	guardRep, err := guard.BuildGuardReport(ctx, archRules, absPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "guard error: %v\n", err)
		return 1
	}
	switch o.format {
	case "json":
		data, _ := guard.FormatGuardJSON(guardRep)
		fmt.Println(string(data))
	default:
		fmt.Print(guard.FormatGuardText(guardRep))
	}
	return 0
}

// ─── explain ───

// explainOpts holds parsed explain command flags.
type explainOpts struct {
	symbol string
	format string
	dir    string
}

// parseExplainFlags parses explain command-line flags.
func parseExplainFlags(args []string) explainOpts {
	o := explainOpts{format: "text", dir: ""}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--format", "-f":
			i++
			if i < len(args) {
				o.format = args[i]
			}
		case "--dir":
			i++
			if i < len(args) {
				o.dir = args[i]
			}
		default:
			if !strings.HasPrefix(args[i], "-") {
				o.symbol = args[i]
			}
		}
	}
	return o
}

// resolveExplanation tries an unused explanation first, then a dead-code one.
func resolveExplanation(ctx *analyzer.Context, symbol string) (*explain.Explanation, error) {
	exp, err := explain.ExplainUnused(ctx, symbol)
	if err != nil || exp == nil {
		exp, err = explain.ExplainDead(ctx, symbol)
	}
	return exp, err
}

func runExplain(args []string) int {
	o := parseExplainFlags(args)
	if o.symbol == "" {
		fmt.Fprintln(os.Stderr, "usage: gollaw explain <symbol>")
		return 1
	}
	ctx, _, code := loadResult(o.dir)
	if code != 0 {
		return code
	}
	exp, err := resolveExplanation(ctx, o.symbol)
	if err != nil {
		fmt.Fprintf(os.Stderr, "explain error: %v\n", err)
		return 1
	}
	if exp == nil {
		fmt.Printf("symbol %q not found\n", o.symbol)
		return 1
	}
	switch o.format {
	case "json":
		data, _ := json.MarshalIndent(exp, "", "  ")
		fmt.Println(string(data))
	default:
		fmt.Print(explain.FormatExplanation(exp))
	}
	return 0
}

// ─── trace ───

// traceOpts holds parsed trace command flags.
type traceOpts struct {
	symbol    string
	direction string
	format    string
	dir       string
	maxDepth  int
}

// parseTraceFlags parses trace command-line flags.
func parseTraceFlags(args []string) traceOpts {
	o := traceOpts{direction: "callers", format: "text", dir: "", maxDepth: 10}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--direction":
			assignNextString(args, &i, &o.direction)
		case "--format", "-f":
			assignNextString(args, &i, &o.format)
		case "--dir":
			assignNextString(args, &i, &o.dir)
		case "--max-depth":
			i++
			if i < len(args) {
				fmt.Sscanf(args[i], "%d", &o.maxDepth)
			}
		default:
			if !strings.HasPrefix(args[i], "-") {
				o.symbol = args[i]
			}
		}
	}
	return o
}

// traceForDirection dispatches the trace call based on the direction flag.
func traceForDirection(ctx *analyzer.Context, symbol, direction string, maxDepth int) (*trace.TraceResult, error) {
	if direction == "callees" {
		return trace.TraceCallees(ctx, symbol, maxDepth)
	}
	return trace.TraceCallers(ctx, symbol, maxDepth)
}

func runTrace(args []string) int {
	o := parseTraceFlags(args)
	if o.symbol == "" {
		fmt.Fprintln(os.Stderr, "usage: gollaw trace <symbol> [--direction callers|callees]")
		return 1
	}
	ctx, _, code := loadResult(o.dir)
	if code != 0 {
		return code
	}
	tr, err := traceForDirection(ctx, o.symbol, o.direction, o.maxDepth)
	if err != nil {
		fmt.Fprintf(os.Stderr, "trace error: %v\n", err)
		return 1
	}
	if tr == nil {
		fmt.Printf("symbol %q not found\n", o.symbol)
		return 1
	}
	switch o.format {
	case "json":
		data, _ := json.MarshalIndent(tr, "", "  ")
		fmt.Println(string(data))
	default:
		fmt.Print(trace.FormatTraceText(tr))
	}
	return 0
}

// ─── baseline ───

// parseBaselineArgs extracts the baseline subcommand and --dir flag.
func parseBaselineArgs(args []string) (sub string, dir string) {
	if len(args) < 1 {
		return "", ""
	}
	sub = args[0]
	for i := 1; i < len(args); i++ {
		if args[i] == "--dir" && i+1 < len(args) {
			dir = args[i+1]
			i++
		}
	}
	return sub, dir
}

// printFindingsList prints a list of findings indented under a section header.
func printFindingsList(findings []analyzer.Finding) {
	for _, f := range findings {
		fmt.Printf("  %s %s:%d %s\n", f.Severity, f.File, f.Line, f.Message)
	}
}

func runBaselineSave(dir string) int {
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
}

func runBaselineDiff(dir string) int {
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
	printFindingsList(newFindings)
	return 0
}

func runBaselineShow(dir string) int {
	bl, err := baseline.Load(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load baseline: %v\n", err)
		return 1
	}
	fmt.Printf("Baseline: %d findings\n", len(bl))
	printFindingsList(bl)
	return 0
}

func runBaseline(args []string) int {
	sub, dir := parseBaselineArgs(args)
	if sub == "" {
		fmt.Fprintln(os.Stderr, "usage: gollaw baseline <save|diff|show>")
		return 1
	}
	switch sub {
	case "save":
		return runBaselineSave(dir)
	case "diff":
		return runBaselineDiff(dir)
	case "show":
		return runBaselineShow(dir)
	default:
		fmt.Fprintf(os.Stderr, "unknown baseline command: %s\n", sub)
		return 1
	}
}

// ─── health ───

func runHealth(args []string) int {
	o := parseFormatDir(args)
	rep, _, code := loadSimple(o.dir)
	if code != 0 {
		return code
	}
	printHealthScore(o.format, rep.HealthScore)
	return 0
}

// printHealthScore outputs the health score in text or JSON format.
func printHealthScore(format string, hs reporter.HealthScore) {
	switch format {
	case "json":
		data, _ := json.MarshalIndent(hs, "", "  ")
		fmt.Println(string(data))
	default:
		fmt.Printf("Health Score: %d/100 (grade: %s)\n", hs.Score, hs.Grade)
		printHealthCategories(hs.ByCategory)
	}
}

// printHealthCategories prints the by-category breakdown.
func printHealthCategories(cats map[string]int) {
	if len(cats) == 0 {
		return
	}
	fmt.Println("  by category:")
	for cat, penalty := range cats {
		fmt.Printf("    %s: -%d\n", cat, penalty)
	}
}

// ─── file-scores ───

func runFileScores(args []string) int {
	o := parseFormatDir(args)
	rep, _, code := loadSimple(o.dir)
	if code != 0 {
		return code
	}
	scores := filescore.ScoreFiles(rep.Findings, nil)
	printJSONOrText(o.format,
		func() ([]byte, error) { return json.MarshalIndent(scores, "", "  ") },
		func() string { return filescore.FormatFileScoresText(scores) })
	return 0
}

// ─── xref ───

func runXRef(args []string) int {
	o := parseFormatDir(args)
	rep, _, code := loadSimple(o.dir)
	if code != 0 {
		return code
	}
	combined := xref.CrossReference(rep.Findings)
	printJSONOrText(o.format,
		func() ([]byte, error) { return json.MarshalIndent(combined, "", "  ") },
		func() string { return xref.FormatXRefText(combined) })
	return 0
}

// ─── public-api ───

func runPublicAPI(args []string) int {
	o := parseFormatDir(args)
	ctx, _, code := loadResult(o.dir)
	if code != 0 {
		return code
	}
	apiRep, err := publicapi.AnalyzePublicAPI(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "public-api error: %v\n", err)
		return 1
	}
	printJSONOrText(o.format,
		func() ([]byte, error) { return publicapi.FormatPublicAPIJSON(apiRep) },
		func() string { return publicapi.FormatPublicAPIText(apiRep) })
	return 0
}

// ─── coverage ───

func runCoverage(args []string) int {
	o := parseFormatDir(args)
	ctx, _, code := loadResult(o.dir)
	if code != 0 {
		return code
	}
	covRep, err := coverage.AnalyzeCoverage(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "coverage error: %v\n", err)
		return 1
	}
	printJSONOrText(o.format,
		func() ([]byte, error) { return coverage.FormatCoverageJSON(covRep) },
		func() string { return coverage.FormatCoverageText(covRep) })
	return 0
}

// ─── owners ───

func runOwners(args []string) int {
	o := parseFormatDir(args)
	rep, _, code := loadSimple(o.dir)
	if code != 0 {
		return code
	}
	groups, err := loadOwnerGroups(rep.Findings, o.dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	printJSONOrText(o.format,
		func() ([]byte, error) { return codeowners.FormatOwnershipJSON(groups) },
		func() string { return codeowners.FormatOwnershipText(groups) })
	return 0
}

// loadOwnerGroups loads CODEOWNERS and groups findings by owner.
func loadOwnerGroups(findings []analyzer.Finding, dir string) (map[string][]analyzer.Finding, error) {
	ownersFile, err := codeowners.FindCodeOwnersFile(dir)
	if err != nil {
		return nil, fmt.Errorf("no CODEOWNERS file found: %w", err)
	}
	owners, err := codeowners.Parse(ownersFile)
	if err != nil {
		return nil, fmt.Errorf("parse CODEOWNERS: %w", err)
	}
	return codeowners.GroupByOwner(findings, owners), nil
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

// defaultGollawConfig is the template written by `gollaw init`.
const defaultGollawConfig = `# Gollaw configuration
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

func runInit(args []string) int {
	dir := "."
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		dir = args[0]
	}
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
	if err := os.WriteFile(configPath, []byte(defaultGollawConfig), 0644); err != nil {
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

const usageText = `Gollaw — whole-codebase intelligence for Go

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
  gollaw mcp  # for AI agent integration`

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

// ─── fix ───

func runFix(args []string) int {
	var (
		dir          = "."
		analyzerName string
		dryRun       = false
		format       = "text"
	)
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--dir":
			i++
			if i < len(args) {
				dir = args[i]
			}
		case "--analyzer":
			i++
			if i < len(args) {
				analyzerName = args[i]
			}
		case "--dry-run":
			dryRun = true
		case "--format", "-f":
			i++
			if i < len(args) {
				format = args[i]
			}
		}
	}

	report, err := fix.RunFix(dir, analyzerName, dryRun)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fix error: %v\n", err)
		return 1
	}

	switch format {
	case "json":
		data, _ := json.MarshalIndent(report, "", "  ")
		fmt.Println(string(data))
	default:
		fmt.Print(fix.FormatFixText(report))
	}
	return 0
}

// ─── inspect ───

// inspectOpts holds parsed inspect command flags.
type inspectOpts struct {
	target string
	dir    string
	format string
}

// parseInspectFlags parses inspect command-line flags.
func parseInspectFlags(args []string) inspectOpts {
	o := inspectOpts{dir: ".", format: "text"}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--dir":
			i++
			if i < len(args) {
				o.dir = args[i]
			}
		case "--format", "-f":
			i++
			if i < len(args) {
				o.format = args[i]
			}
		default:
			if !strings.HasPrefix(args[i], "-") {
				o.target = args[i]
			}
		}
	}
	return o
}

func runInspect(args []string) int {
	o := parseInspectFlags(args)
	if o.target == "" {
		fmt.Fprintln(os.Stderr, "usage: gollaw inspect <file|symbol>")
		return 1
	}
	ctx, _, code := loadResult(o.dir)
	if code != 0 {
		return code
	}
	inspectResult, err := inspect.Inspect(ctx, o.target, o.dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "inspect error: %v\n", err)
		return 1
	}
	switch o.format {
	case "json":
		data, _ := inspect.FormatInspectJSON(inspectResult)
		fmt.Println(string(data))
	default:
		fmt.Print(inspect.FormatInspectText(inspectResult))
	}
	return 0
}

// ─── migrate ───

func runMigrate(args []string) int {
	var (
		source = ""
		dir    = "."
	)
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--from":
			i++
			if i < len(args) {
				source = args[i]
			}
		case "--dir":
			i++
			if i < len(args) {
				dir = args[i]
			}
		}
	}

	result, err := migrate.Migrate(source, dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "migrate error: %v\n", err)
		return 1
	}

	fmt.Print(migrate.FormatMigrateText(result))
	return 0
}

// ─── regression ───

func runRegression(args []string) int {
	var (
		dir       = "."
		tolerance = 0
		format    = "text"
	)
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--dir":
			i++
			if i < len(args) {
				dir = args[i]
			}
		case "--tolerance":
			i++
			if i < len(args) {
				fmt.Sscanf(args[i], "%d", &tolerance)
			}
		case "--format", "-f":
			i++
			if i < len(args) {
				format = args[i]
			}
		}
	}

	result, err := regression.RunRegression(dir, tolerance)
	if err != nil {
		fmt.Fprintf(os.Stderr, "regression error: %v\n", err)
		return 1
	}

	switch format {
	case "json":
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))
	default:
		fmt.Print(regression.FormatRegressionText(result))
	}

	if result.Outcome == "fail" {
		return 1
	}
	return 0
}

// ─── walkthrough ───

func runWalkthrough(args []string) int {
	var (
		dir    = "."
		format = "text"
	)
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--dir":
			i++
			if i < len(args) {
				dir = args[i]
			}
		case "--format", "-f":
			i++
			if i < len(args) {
				format = args[i]
			}
		}
	}

	rep, _, _, code := loadAndAnalyze([]string{"--dir", dir, "--no-config"})
	if code != 0 {
		return code
	}

	wt := walkthrough.GenerateWalkthrough(rep.Findings, rep.Stats)
	switch format {
	case "json":
		data, _ := json.MarshalIndent(wt, "", "  ")
		fmt.Println(string(data))
	default:
		fmt.Print(walkthrough.FormatWalkthroughText(wt))
	}
	return 0
}

// ─── rule-pack ───

func runRulePack(args []string) int {
	if len(args) < 1 {
		packs := rulepack.BuiltInPacks()
		fmt.Print(rulepack.FormatPacksText(packs))
		return 0
	}

	switch args[0] {
	case "list":
		packs := rulepack.BuiltInPacks()
		fmt.Print(rulepack.FormatPacksText(packs))
		return 0
	case "apply":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: gollaw rule-pack apply <name>")
			return 1
		}
		dir := "."
		for i := 2; i < len(args); i++ {
			if args[i] == "--dir" && i+1 < len(args) {
				dir = args[i+1]
				i++
			}
		}
		if err := rulepack.ApplyPack(args[1], dir); err != nil {
			fmt.Fprintf(os.Stderr, "apply error: %v\n", err)
			return 1
		}
		fmt.Printf("Rule pack %q applied to .gollaw.yaml\n", args[1])
		return 0
	case "show":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: gollaw rule-pack show <name>")
			return 1
		}
		pack, err := rulepack.GetPack(args[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			return 1
		}
		packs := []rulepack.RulePack{*pack}
		fmt.Print(rulepack.FormatPacksText(packs))
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown rule-pack command: %s\n", args[0])
		return 1
	}
}

// ─── impact ───

// impactOpts holds parsed impact command flags.
type impactOpts struct {
	dir         string
	format      string
	baseRef     string
	changedOnly bool
}

// parseImpactFlags parses impact command-line flags.
func parseImpactFlags(args []string) impactOpts {
	o := impactOpts{dir: ".", format: "text"}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--dir":
			i++
			if i < len(args) {
				o.dir = args[i]
			}
		case "--format", "-f":
			i++
			if i < len(args) {
				o.format = args[i]
			}
		case "--base-ref":
			i++
			if i < len(args) {
				o.baseRef = args[i]
				o.changedOnly = true
			}
		}
	}
	return o
}

func runImpact(args []string) int {
	o := parseImpactFlags(args)
	ctx, _, code := loadResult(o.dir)
	if code != 0 {
		return code
	}
	g := graph.BuildGraph(ctx)
	var changedFiles []string
	if o.changedOnly && o.baseRef != "" {
		changedFiles, _ = audit.GetChangedFiles(o.baseRef, o.dir)
	}
	impactRep := graph.BuildImpactReport(g, changedFiles)
	switch o.format {
	case "json":
		data, _ := graph.FormatImpactJSON(impactRep)
		fmt.Println(string(data))
	default:
		fmt.Print(graph.FormatImpactText(impactRep))
	}
	return 0
}

// ─── vital-signs ───

func runVitalSigns(args []string) int {
	o := parseFormatDir(args)
	rep, scores, code := loadAndScore(o.dir)
	if code != 0 {
		return code
	}
	vs := health.ComputeVitalSigns(rep.Findings, rep.Stats, scores, 0)
	printJSONOrText(o.format,
		func() ([]byte, error) { return health.FormatVitalSignsJSON(vs) },
		func() string { return health.FormatVitalSignsText(vs) })
	return 0
}

// ─── targets ───

func runTargets(args []string) int {
	o := parseFormatDir(args)
	rep, scores, code := loadAndScore(o.dir)
	if code != 0 {
		return code
	}
	targets := health.ComputeRefactoringTargets(rep.Findings, scores)
	printJSONOrText(o.format,
		func() ([]byte, error) { return health.FormatTargetsJSON(targets) },
		func() string { return health.FormatTargetsText(targets) })
	return 0
}

// ─── trends ───

// trendsOpts holds parsed trends command flags.
type trendsOpts struct {
	dir    string
	format string
	save   bool
}

// parseTrendsFlags parses trends command-line flags.
func parseTrendsFlags(args []string) trendsOpts {
	o := trendsOpts{dir: ".", format: "text"}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--dir":
			i++
			if i < len(args) {
				o.dir = args[i]
			}
		case "--format", "-f":
			i++
			if i < len(args) {
				o.format = args[i]
			}
		case "--save":
			o.save = true
		}
	}
	return o
}

func runTrendsSave(dir string) int {
	rep, scores, code := loadAndScore(dir)
	if code != 0 {
		return code
	}
	vs := health.ComputeVitalSigns(rep.Findings, rep.Stats, scores, 0)
	if err := health.SaveSnapshot(dir, vs); err != nil {
		fmt.Fprintf(os.Stderr, "save snapshot: %v\n", err)
		return 1
	}
	fmt.Println("Snapshot saved.")
	return 0
}

func runTrendsShow(dir, format string) int {
	result, err := health.LoadTrends(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load trends: %v\n", err)
		return 1
	}
	printJSONOrText(format,
		func() ([]byte, error) { return health.FormatTrendsJSON(result) },
		func() string { return health.FormatTrendsText(result) })
	return 0
}

func runTrends(args []string) int {
	o := parseTrendsFlags(args)
	if o.save {
		return runTrendsSave(o.dir)
	}
	return runTrendsShow(o.dir, o.format)
}

// ─── timings ───

// timingsOpts holds parsed timings command flags.
type timingsOpts struct {
	dir    string
	format string
}

// parseTimingsFlags parses timings command-line flags.
func parseTimingsFlags(args []string) timingsOpts {
	o := timingsOpts{dir: ".", format: "text"}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--dir":
			i++
			if i < len(args) {
				o.dir = args[i]
			}
		case "--format", "-f":
			i++
			if i < len(args) {
				o.format = args[i]
			}
		}
	}
	return o
}

func runTimings(args []string) int {
	o := parseTimingsFlags(args)
	ctx, _, code := loadResult(o.dir)
	if code != 0 {
		return code
	}
	timer := health.NewTimer()
	registry := analyzer.NewRegistry()
	for _, a := range registry.All() {
		findings, err := a.Analyze(ctx)
		if err != nil {
			continue
		}
		timer.Record(a.Name(), len(findings))
	}
	timingReport := timer.Report()
	switch o.format {
	case "json":
		data, _ := health.FormatTimingsJSON(timingReport)
		fmt.Println(string(data))
	default:
		fmt.Print(health.FormatTimingsText(timingReport))
	}
	return 0
}

// ─── filterBySeverity ───

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

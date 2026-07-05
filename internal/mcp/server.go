// Package mcp implements a minimal Model Context Protocol server for Gollaw.
// It exposes Gollaw's analysis capabilities as tools that AI agents can call.
// The protocol is implemented directly over JSON-RPC 2.0 with Content-Length framing.
package mcp

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/dovocoder/gollaw/internal/analyzer"
	"github.com/dovocoder/gollaw/internal/audit"
	"github.com/dovocoder/gollaw/internal/baseline"
	"github.com/dovocoder/gollaw/internal/codeowners"
	"github.com/dovocoder/gollaw/internal/config"
	"github.com/dovocoder/gollaw/internal/coverage"
	"github.com/dovocoder/gollaw/internal/explain"
	"github.com/dovocoder/gollaw/internal/filescore"
	"github.com/dovocoder/gollaw/internal/guard"
	"github.com/dovocoder/gollaw/internal/jsonrpc"
	"github.com/dovocoder/gollaw/internal/loader"
	"github.com/dovocoder/gollaw/internal/publicapi"
	"github.com/dovocoder/gollaw/internal/reporter"
	"github.com/dovocoder/gollaw/internal/suppress"
	"github.com/dovocoder/gollaw/internal/trace"
	"github.com/dovocoder/gollaw/internal/xref"
	"golang.org/x/tools/go/packages"
)

const protocolVersion = "2024-11-05"

// mcpVersion is the MCP server version (mirrors cli.Version to avoid an import cycle).
const mcpVersion = "0.2.0"

// ServeMCP runs the MCP server loop over the given reader/writer (typically stdio).
func ServeMCP(in io.Reader, out io.Writer) error {
	s := &server{
		conn: jsonrpc.NewConn(in, out),
	}
	return s.run()
}

// ─── Server struct ─────────────────────────────────────────────────────

type server struct {
	conn *jsonrpc.Conn
}

// ─── JSON-RPC types ────────────────────────────────────────────────────

type rpcMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type initializeParams struct {
	ProtocolVersion string          `json:"protocolVersion"`
	Capabilities    json.RawMessage `json:"capabilities"`
	ClientInfo      clientInfo      `json:"clientInfo"`
}

type clientInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type initializeResult struct {
	ProtocolVersion string          `json:"protocolVersion"`
	Capabilities    serverCaps      `json:"capabilities"`
	ServerInfo      serverInfo      `json:"serverInfo"`
}

type serverCaps struct {
	Tools json.RawMessage `json:"tools"`
}

type serverInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type toolDef struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	InputSchema interface{} `json:"inputSchema"`
}

type toolsListResult struct {
	Tools []toolDef `json:"tools"`
}

type callToolParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

type callToolResult struct {
	Content []contentBlock `json:"content"`
	IsError bool           `json:"isError,omitempty"`
}

type contentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// ─── Main loop ──────────────────────────────────────────────────────────

func (s *server) run() error {
	for {
		msg, err := s.readMessage()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}

		var rpc rpcMessage
		if err := json.Unmarshal(msg, &rpc); err != nil {
			continue
		}

		switch rpc.Method {
		case "initialize":
			s.handleInitialize(rpc.ID, rpc.Params)
		case "initialized":
			// notification — no response
		case "shutdown":
			s.sendResponse(rpc.ID, nil)
		case "tools/list":
			s.handleToolsList(rpc.ID)
		case "tools/call":
			s.handleToolsCall(rpc.ID, rpc.Params)
		default:
			if len(rpc.ID) > 0 {
				s.sendError(rpc.ID, -32601, fmt.Sprintf("method not found: %s", rpc.Method))
			}
		}
	}
}

// ─── Message framing ───────────────────────────────────────────────────

// ─── JSON-RPC delegation ───────────────────────────────────────────────
func (s *server) readMessage() ([]byte, error)  { return s.conn.ReadMessage() }
func (s *server) writeMessage(data []byte) error { return s.conn.WriteMessage(data) }
func (s *server) sendResponse(id json.RawMessage, result interface{}) {
	s.conn.SendResponse(id, result)
}
func (s *server) sendError(id json.RawMessage, code int, message string) {
	s.conn.SendError(id, code, message)
}

// ─── Handlers ──────────────────────────────────────────────────────────

func (s *server) handleInitialize(id json.RawMessage, params json.RawMessage) {
	result := initializeResult{
		ProtocolVersion: protocolVersion,
		Capabilities: serverCaps{
			Tools: json.RawMessage(`{}`),
		},
		ServerInfo: serverInfo{
			Name:    "gollaw",
			Version: mcpVersion,
		},
	}
	s.sendResponse(id, result)
}

// toolHandler is a dispatch entry for a tool call.
type toolHandler func(s *server, id json.RawMessage, args json.RawMessage)

// toolDispatch maps tool names to their handler functions.
var toolDispatch = map[string]toolHandler{
	"gollaw_analyze":         func(s *server, id, args json.RawMessage) { s.toolAnalyze(id, args) },
	"gollaw_list_analyzers":  func(s *server, id, _ json.RawMessage) { s.toolListAnalyzers(id) },
	"gollaw_explain":         func(s *server, id, args json.RawMessage) { s.toolExplain(id, args) },
	"gollaw_trace":           func(s *server, id, args json.RawMessage) { s.toolTrace(id, args) },
	"gollaw_health":          func(s *server, id, args json.RawMessage) { s.toolHealth(id, args) },
	"gollaw_audit":           func(s *server, id, args json.RawMessage) { s.toolAudit(id, args) },
	"gollaw_guard":           func(s *server, id, args json.RawMessage) { s.toolGuard(id, args) },
	"gollaw_baseline_save":   func(s *server, id, args json.RawMessage) { s.toolBaselineSave(id, args) },
	"gollaw_baseline_diff":   func(s *server, id, args json.RawMessage) { s.toolBaselineDiff(id, args) },
	"gollaw_public_api":      func(s *server, id, args json.RawMessage) { s.toolPublicAPI(id, args) },
	"gollaw_coverage":        func(s *server, id, args json.RawMessage) { s.toolCoverage(id, args) },
	"gollaw_file_scores":     func(s *server, id, args json.RawMessage) { s.toolFileScores(id, args) },
	"gollaw_xref":            func(s *server, id, args json.RawMessage) { s.toolXRef(id, args) },
	"gollaw_dupes":           func(s *server, id, args json.RawMessage) { s.toolDupes(id, args) },
	"gollaw_security":        func(s *server, id, args json.RawMessage) { s.toolSecurity(id, args) },
	"gollaw_impact":          func(s *server, id, args json.RawMessage) { s.toolImpact(id, args) },
	"gollaw_inspect":         func(s *server, id, args json.RawMessage) { s.toolInspect(id, args) },
	"gollaw_list_boundaries": func(s *server, id, args json.RawMessage) { s.toolListBoundaries(id, args) },
	"gollaw_project_info":    func(s *server, id, args json.RawMessage) { s.toolProjectInfo(id, args) },
	"gollaw_check_changed":   func(s *server, id, args json.RawMessage) { s.toolCheckChanged(id, args) },
	"gollaw_suppress":        func(s *server, id, args json.RawMessage) { s.toolSuppress(id, args) },
	"gollaw_owners":          func(s *server, id, args json.RawMessage) { s.toolOwners(id, args) },
	"gollaw_fix_preview":     func(s *server, id, args json.RawMessage) { s.toolFixPreview(id, args) },
}

func (s *server) handleToolsCall(id json.RawMessage, params json.RawMessage) {
	var p callToolParams
	if err := json.Unmarshal(params, &p); err != nil {
		s.sendError(id, -32602, "invalid tools/call params")
		return
	}

	handler, ok := toolDispatch[p.Name]
	if !ok {
		s.sendError(id, -32602, fmt.Sprintf("unknown tool: %s", p.Name))
		return
	}
	handler(s, id, p.Arguments)
}

// ─── Tool handlers ─────────────────────────────────────────────────────

func (s *server) toolAnalyze(id json.RawMessage, args json.RawMessage) {
	var p struct {
		Dir      string   `json:"dir"`
		Patterns []string `json:"patterns"`
	}
	if len(args) > 0 {
		json.Unmarshal(args, &p)
	}
	if len(p.Patterns) == 0 {
		p.Patterns = []string{"./..."}
	}
	dir := p.Dir

	ctx, findings, err := loadAndAnalyze(dir, p.Patterns)
	if err != nil {
		s.sendToolError(id, err)
		return
	}
	_ = ctx

	// Build a report.
	stats := reporter.CodebaseStats{}
	result, _ := loader.Load(loader.LoadConfig{Patterns: p.Patterns, Dir: dir})
	if result != nil {
		stats = reporter.CodebaseStats{
			Packages:  result.Stats.PackageCount,
			Files:     result.Stats.FileCount,
			Functions: result.Stats.FunctionCount,
			Types:     result.Stats.TypeCount,
			Decls:     result.Stats.DeclCount,
		}
	}
	rep := reporter.BuildReport("0.1.0", p.Patterns, nil, stats, findings)

	s.sendToolJSON(id, rep)
}

func (s *server) toolListAnalyzers(id json.RawMessage) {
	registry := analyzer.NewRegistry()
	type analyzerInfo struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Category    string `json:"category"`
	}
	var list []analyzerInfo
	for _, a := range registry.All() {
		list = append(list, analyzerInfo{
			Name:        a.Name(),
			Description: a.Description(),
			Category:    string(a.Category()),
		})
	}
	s.sendToolJSON(id, list)
}

func (s *server) toolExplain(id json.RawMessage, args json.RawMessage) {
	var p struct {
		Dir    string `json:"dir"`
		Symbol string `json:"symbol"`
	}
	if err := json.Unmarshal(args, &p); err != nil {
		s.sendError(id, -32602, "invalid arguments")
		return
	}
	if p.Symbol == "" {
		s.sendError(id, -32602, "symbol is required")
		return
	}
	dir := p.Dir

	ctx, _, err := loadAndAnalyze(dir, []string{"./..."})
	if err != nil {
		s.sendToolError(id, err)
		return
	}

	expl, err := explain.ExplainUnused(ctx, p.Symbol)
	if err != nil {
		s.sendToolError(id, err)
		return
	}

	s.sendToolJSON(id, expl)
}

func (s *server) toolTrace(id json.RawMessage, args json.RawMessage) {
	var p struct {
		Dir       string `json:"dir"`
		Symbol    string `json:"symbol"`
		Direction string `json:"direction"`
		MaxDepth  int    `json:"maxDepth"`
	}
	if err := json.Unmarshal(args, &p); err != nil {
		s.sendError(id, -32602, "invalid arguments")
		return
	}
	if p.Symbol == "" {
		s.sendError(id, -32602, "symbol is required")
		return
	}
	if p.Direction == "" {
		p.Direction = "callers"
	}
	dir := p.Dir

	ctx, _, err := loadAndAnalyze(dir, []string{"./..."})
	if err != nil {
		s.sendToolError(id, err)
		return
	}

	var result *trace.TraceResult
	switch p.Direction {
	case "callers":
		result, err = trace.TraceCallers(ctx, p.Symbol, p.MaxDepth)
	case "callees":
		result, err = trace.TraceCallees(ctx, p.Symbol, p.MaxDepth)
	default:
		s.sendError(id, -32602, fmt.Sprintf("invalid direction: %s (use callers or callees)", p.Direction))
		return
	}
	if err != nil {
		s.sendToolError(id, err)
		return
	}

	s.sendToolJSON(id, result)
}

func (s *server) toolHealth(id json.RawMessage, args json.RawMessage) {
	dir := parseDirArgs(args)

	_, findings, ok := s.loadAndAnalyzeOrError(id, dir)
	if !ok {
		return
	}

	rep := reporter.BuildReport("0.1.0", []string{"./..."}, nil, reporter.CodebaseStats{}, findings)
	health := rep.HealthScore
	data, _ := json.MarshalIndent(map[string]interface{}{
		"score":      health.Score,
		"grade":      health.Grade,
		"byCategory": health.ByCategory,
		"totalFindings": len(findings),
	}, "", "  ")
	s.sendResponse(id, callToolResult{
		Content: []contentBlock{{Type: "text", Text: string(data)}},
	})
}

// ─── New tool handlers ─────────────────────────────────────────────────

func (s *server) toolAudit(id json.RawMessage, args json.RawMessage) {
	dir, baseRef := parseDirBaseRefArgs(args)

	ctx, findings, ok := s.loadAndAnalyzeOrError(id, dir)
	if !ok {
		return
	}

	auditRep, err := audit.RunAudit(ctx, baseRef, findings, dir)
	if err != nil {
		s.sendToolError(id, err)
		return
	}

	s.sendToolJSON(id, auditRep)
}

func (s *server) toolGuard(id json.RawMessage, args json.RawMessage) {
	var p struct {
		FilePath string   `json:"file_path"`
		Dir      string   `json:"dir"`
		Rules    []string `json:"rules"`
	}
	if len(args) > 0 {
		json.Unmarshal(args, &p)
	}
	if p.FilePath == "" {
		s.sendError(id, -32602, "file_path is required")
		return
	}
	dir := p.Dir

	archRules := parseArchRules(p.Rules)
	if len(archRules) == 0 {
		archRules = loadConfigRules(dir)
	}

	result, err := loader.Load(loader.LoadConfig{Patterns: []string{"./..."}, Dir: dir})
	if err != nil {
		s.sendToolError(id, err)
		return
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

	absPath, _ := filepath.Abs(p.FilePath)
	guardRep, err := guard.BuildGuardReport(ctx, archRules, absPath)
	if err != nil {
		s.sendToolError(id, err)
		return
	}

	s.sendToolJSON(id, guardRep)
}

// parseArchRules parses rule strings of the form "pkg must not import other"
// into analyzer.Rule values.
func parseArchRules(ruleStrs []string) []analyzer.Rule {
	var rules []analyzer.Rule
	for _, r := range ruleStrs {
		parts := strings.SplitN(r, " must not import ", 2)
		if len(parts) == 2 {
			rules = append(rules, analyzer.Rule{
				Package:    strings.TrimSpace(parts[0]),
				MustNotUse: strings.TrimSpace(parts[1]),
			})
		}
	}
	return rules
}

// loadConfigRules loads architecture rules from the project's .gollaw.yaml config.
func loadConfigRules(dir string) []analyzer.Rule {
	configPath := config.FindConfig(dir)
	if configPath == "" {
		return nil
	}
	fc, err := config.Load(configPath)
	if err != nil {
		return nil
	}
	return parseArchRules(fc.Rules)
}

func (s *server) toolBaselineSave(id json.RawMessage, args json.RawMessage) {
	dir := parseDirArgs(args)

	_, findings, ok := s.loadAndAnalyzeOrError(id, dir)
	if !ok {
		return
	}

	if err := baseline.Save(dir, findings); err != nil {
		s.sendToolError(id, err)
		return
	}

	data, _ := json.MarshalIndent(map[string]interface{}{
		"savedFindings": len(findings),
		"path":          filepath.Join(dir, ".gollaw", "baseline.json"),
	}, "", "  ")
	s.sendResponse(id, callToolResult{
		Content: []contentBlock{{Type: "text", Text: string(data)}},
	})
}

func (s *server) toolBaselineDiff(id json.RawMessage, args json.RawMessage) {
	dir := parseDirArgs(args)

	_, findings, ok := s.loadAndAnalyzeOrError(id, dir)
	if !ok {
		return
	}

	bl, err := baseline.Load(dir)
	if err != nil {
		s.sendToolError(id, err)
		return
	}

	newFindings := baseline.Diff(bl, findings)
	data, _ := json.MarshalIndent(map[string]interface{}{
		"baselineCount": len(bl),
		"currentCount":   len(findings),
		"newFindings":    newFindings,
		"newCount":       len(newFindings),
	}, "", "  ")
	s.sendResponse(id, callToolResult{
		Content: []contentBlock{{Type: "text", Text: string(data)}},
	})
}

func (s *server) toolPublicAPI(id json.RawMessage, args json.RawMessage) {
	dir := parseDirArgs(args)

	ctx, _, err := loadAndAnalyze(dir, []string{"./..."})
	if err != nil {
		s.sendToolError(id, err)
		return
	}

	apiRep, err := publicapi.AnalyzePublicAPI(ctx)
	if err != nil {
		s.sendToolError(id, err)
		return
	}

	s.sendToolJSON(id, apiRep)
}

func (s *server) toolCoverage(id json.RawMessage, args json.RawMessage) {
	dir := parseDirArgs(args)

	ctx, _, err := loadAndAnalyze(dir, []string{"./..."})
	if err != nil {
		s.sendToolError(id, err)
		return
	}

	covRep, err := coverage.AnalyzeCoverage(ctx)
	if err != nil {
		s.sendToolError(id, err)
		return
	}

	s.sendToolJSON(id, covRep)
}

func (s *server) toolFileScores(id json.RawMessage, args json.RawMessage) {
	dir := parseDirArgs(args)

	_, findings, ok := s.loadAndAnalyzeOrError(id, dir)
	if !ok {
		return
	}

	scores := filescore.ScoreFiles(findings, nil)
	s.sendToolJSON(id, scores)
}

func (s *server) toolXRef(id json.RawMessage, args json.RawMessage) {
	dir := parseDirArgs(args)

	_, findings, ok := s.loadAndAnalyzeOrError(id, dir)
	if !ok {
		return
	}

	combined := xref.CrossReference(findings)
	s.sendToolJSON(id, combined)
}

func (s *server) toolDupes(id json.RawMessage, args json.RawMessage) {
	s.runSingleAnalyzer(id, args, "duplication")
}

func (s *server) toolSecurity(id json.RawMessage, args json.RawMessage) {
	s.runSingleAnalyzer(id, args, "security")
}

// runSingleAnalyzer is a shared helper for tool handlers that run a single
// analyzer by name and return its findings.
func (s *server) runSingleAnalyzer(id json.RawMessage, args json.RawMessage, name string) {
	dir := parseDirArgs(args)
	findings, err := runAnalyzersByName(dir, []string{name})
	if err != nil {
		s.sendToolError(id, err)
		return
	}
	s.sendToolJSON(id, findings)
}

func (s *server) toolImpact(id json.RawMessage, args json.RawMessage) {
	dir := parseDirArgs(args)

	_, findings, ok := s.loadAndAnalyzeOrError(id, dir)
	if !ok {
		return
	}

	bySeverity := make(map[string]int)
	byCategory := make(map[string]int)
	byAnalyzer := make(map[string]int)
	for _, f := range findings {
		bySeverity[string(f.Severity)]++
		byCategory[string(f.Category)]++
		byAnalyzer[f.Analyzer]++
	}

	data, _ := json.MarshalIndent(map[string]interface{}{
		"totalFindings": len(findings),
		"bySeverity":    bySeverity,
		"byCategory":    byCategory,
		"byAnalyzer":    byAnalyzer,
	}, "", "  ")
	s.sendResponse(id, callToolResult{
		Content: []contentBlock{{Type: "text", Text: string(data)}},
	})
}

func (s *server) toolInspect(id json.RawMessage, args json.RawMessage) {
	var p struct {
		Target string `json:"target"`
		Dir    string `json:"dir"`
	}
	if len(args) > 0 {
		json.Unmarshal(args, &p)
	}
	if p.Target == "" {
		s.sendError(id, -32602, "target is required")
		return
	}
	dir := p.Dir

	ctx, findings, ok := s.loadAndAnalyzeOrError(id, dir)
	if !ok {
		return
	}

	// Check if target looks like a file path.
	isFile := strings.HasSuffix(p.Target, ".go") || filepath.Ext(p.Target) != ""
	if isFile {
		result := s.inspectFile(ctx, findings, p.Target)
		s.sendToolJSON(id, result)
		return
	}

	// Otherwise treat target as a symbol name.
	result := s.inspectSymbol(ctx, findings, p.Target)
	s.sendToolJSON(id, result)
}

func (s *server) inspectFile(ctx *analyzer.Context, findings []analyzer.Finding, target string) map[string]interface{} {
	absTarget, _ := filepath.Abs(target)
	fileFindings := filterFindingsByTarget(findings, target, absTarget)
	pkgPath := findPackageForFile(ctx.Packages, target, absTarget)
	score := fileHealthScore(fileFindings, target)

	return map[string]interface{}{
		"kind":        "file",
		"target":      target,
		"absPath":     absTarget,
		"package":     pkgPath,
		"exists":      fileExists(target),
		"findings":    fileFindings,
		"findingCount": len(fileFindings),
		"healthScore": score,
	}
}

// filterFindingsByTarget returns findings that match the given file path
// (either relative or absolute form).
func filterFindingsByTarget(findings []analyzer.Finding, target, absTarget string) []analyzer.Finding {
	var matched []analyzer.Finding
	for _, f := range findings {
		if f.File == target || f.File == absTarget {
			matched = append(matched, f)
		}
	}
	return matched
}

// findPackageForFile returns the package path containing the given file.
func findPackageForFile(pkgs []*packages.Package, target, absTarget string) string {
	for _, pkg := range pkgs {
		for _, f := range pkg.GoFiles {
			absF, _ := filepath.Abs(f)
			if absF == absTarget || f == target {
				return pkg.PkgPath
			}
		}
	}
	return ""
}

// fileHealthScore returns the health score for a set of file findings.
// If no scores are available, returns a default perfect score.
func fileHealthScore(fileFindings []analyzer.Finding, target string) interface{} {
	scores := filescore.ScoreFiles(fileFindings, nil)
	if len(scores) > 0 {
		return scores[0]
	}
	return map[string]interface{}{
		"file":         target,
		"score":        100,
		"grade":        "A",
		"findingCount": 0,
	}
}

func (s *server) inspectSymbol(ctx *analyzer.Context, findings []analyzer.Finding, target string) map[string]interface{} {
	// Try explain to get symbol info.
	expl, err := explain.ExplainUnused(ctx, target)
	if err != nil || expl == nil {
		expl, err = explain.ExplainDead(ctx, target)
	}

	symbolInfo := map[string]interface{}{
		"kind":     "symbol",
		"target":   target,
		"findings":  []analyzer.Finding{},
	}

	if expl != nil {
		symbolInfo["explanation"] = expl
		symbolInfo["status"] = expl.Status
		symbolInfo["location"] = expl.Location
	}

	// Find findings whose message mentions the symbol or whose file matches the symbol's location.
	var relevantFindings []analyzer.Finding
	if expl != nil {
		locFile := strings.SplitN(expl.Location, ":", 2)[0]
		for _, f := range findings {
			if f.File == locFile || strings.Contains(f.Message, target) {
				relevantFindings = append(relevantFindings, f)
			}
		}
	}
	symbolInfo["findings"] = relevantFindings

	// Try to get call chain via trace callers.
	tr, traceErr := trace.TraceCallers(ctx, target, 10)
	if traceErr == nil && tr != nil {
		symbolInfo["callChain"] = tr
	}

	return symbolInfo
}

func (s *server) toolListBoundaries(id json.RawMessage, args json.RawMessage) {
	dir := parseDirArgs(args)

	archRules := loadConfigRules(dir)

	result, err := loader.Load(loader.LoadConfig{Patterns: []string{"./..."}, Dir: dir})
	if err != nil {
		s.sendToolError(id, err)
		return
	}

	boundaries := buildBoundaries(result.Packages, archRules)

	data, _ := json.MarshalIndent(map[string]interface{}{
		"totalRules":    len(archRules),
		"totalPackages": len(boundaries),
		"boundaries":    boundaries,
	}, "", "  ")
	s.sendResponse(id, callToolResult{
		Content: []contentBlock{{Type: "text", Text: string(data)}},
	})
}

// boundaryInfo describes a package's imports and applicable rules.
type boundaryInfo struct {
	Package string          `json:"package"`
	Imports []string        `json:"imports"`
	Rules   []analyzer.Rule `json:"rules"`
}

// buildBoundaries constructs boundary info for each package with type info,
// collecting sorted imports and applicable architecture rules.
func buildBoundaries(packages []*packages.Package, archRules []analyzer.Rule) []boundaryInfo {
	var boundaries []boundaryInfo
	for _, pkg := range packages {
		if pkg.Types == nil {
			continue
		}
		boundaries = append(boundaries, boundaryInfo{
			Package: pkg.PkgPath,
			Imports: collectSortedImports(pkg),
			Rules:   applicableRulesForPkg(pkg.PkgPath, archRules),
		})
	}
	return boundaries
}

// collectSortedImports returns sorted import paths from a package.
func collectSortedImports(pkg *packages.Package) []string {
	var imports []string
	for _, imp := range pkg.Imports {
		if imp != nil {
			imports = append(imports, imp.PkgPath)
		}
	}
	sort.Strings(imports)
	return imports
}

// applicableRulesForPkg returns rules where the package matches either
// the rule's Package or MustNotUse field.
func applicableRulesForPkg(pkgPath string, rules []analyzer.Rule) []analyzer.Rule {
	var applicable []analyzer.Rule
	for _, rule := range rules {
		if pkgHasSuffixStr(pkgPath, rule.Package) || pkgHasSuffixStr(pkgPath, rule.MustNotUse) {
			applicable = append(applicable, rule)
		}
	}
	return applicable
}

func (s *server) toolProjectInfo(id json.RawMessage, args json.RawMessage) {
	dir := parseDirArgs(args)

	result, err := loader.Load(loader.LoadConfig{Patterns: []string{"./..."}, Dir: dir})
	if err != nil {
		s.sendToolError(id, err)
		return
	}

	// Parse go.mod for module name and Go version.
	moduleName, goVersion := parseGoMod(dir)

	// Count unique dependencies from go.mod.
	depCount := countGoModDeps(dir)

	info := map[string]interface{}{
		"moduleName":    moduleName,
		"goVersion":      goVersion,
		"packageCount":   result.Stats.PackageCount,
		"fileCount":      result.Stats.FileCount,
		"functionCount":  result.Stats.FunctionCount,
		"typeCount":      result.Stats.TypeCount,
		"declCount":      result.Stats.DeclCount,
		"dependencyCount": depCount,
	}

	s.sendToolJSON(id, info)
}

func (s *server) toolCheckChanged(id json.RawMessage, args json.RawMessage) {
	dir, baseRef := parseDirBaseRefArgs(args)

	_, findings, ok := s.loadAndAnalyzeOrError(id, dir)
	if !ok {
		return
	}

	changedFiles, err := getChangedFiles(baseRef, dir)
	if err != nil {
		s.sendToolError(id, err)
		return
	}

	changedSet := buildChangedFileSet(changedFiles, dir)
	changedFindings := filterFindingsByFiles(findings, changedSet)

	data, _ := json.MarshalIndent(map[string]interface{}{
		"baseRef":           baseRef,
		"changedFiles":      changedFiles,
		"changedFileCount":  len(changedFiles),
		"findings":          changedFindings,
		"findingCount":      len(changedFindings),
	}, "", "  ")
	s.sendResponse(id, callToolResult{
		Content: []contentBlock{{Type: "text", Text: string(data)}},
	})
}

// buildChangedFileSet creates a set of changed file paths in multiple forms
// (relative, absolute, and basename) for matching against findings.
func buildChangedFileSet(changedFiles []string, dir string) map[string]bool {
	changedSet := make(map[string]bool)
	for _, f := range changedFiles {
		changedSet[f] = true
		abs, _ := filepath.Abs(filepath.Join(dir, f))
		changedSet[abs] = true
		changedSet[filepath.Base(f)] = true
	}
	return changedSet
}

// filterFindingsByFiles returns findings whose File field is in the given set.
func filterFindingsByFiles(findings []analyzer.Finding, fileSet map[string]bool) []analyzer.Finding {
	var matched []analyzer.Finding
	for _, f := range findings {
		if fileSet[f.File] {
			matched = append(matched, f)
		}
	}
	return matched
}

func (s *server) toolSuppress(id json.RawMessage, args json.RawMessage) {
	dir := parseDirArgs(args)

	ctx, findings, ok := s.loadAndAnalyzeOrError(id, dir)
	if !ok {
		return
	}

	// Parse suppressions from all loaded source files.
	var allFiles []*ast.File
	for _, files := range ctx.SyntaxByPkg {
		allFiles = append(allFiles, files...)
	}
	sup, err := suppress.ParseSuppressions(ctx.FSET, allFiles)
	if err != nil {
		s.sendToolError(id, err)
		return
	}

	stale := suppress.FindStale(findings, sup)
	data, _ := json.MarshalIndent(map[string]interface{}{
		"totalSuppressions": len(sup.Entries()),
		"staleCount":        len(stale),
		"staleSuppressions": stale,
	}, "", "  ")
	s.sendResponse(id, callToolResult{
		Content: []contentBlock{{Type: "text", Text: string(data)}},
	})
}

func (s *server) toolOwners(id json.RawMessage, args json.RawMessage) {
	dir := parseDirArgs(args)

	_, findings, ok := s.loadAndAnalyzeOrError(id, dir)
	if !ok {
		return
	}

	ownersFile, err := codeowners.FindCodeOwnersFile(dir)
	if err != nil {
		s.sendToolError(id, err)
		return
	}

	owners, err := codeowners.Parse(ownersFile)
	if err != nil {
		s.sendToolError(id, err)
		return
	}

	groups := codeowners.GroupByOwner(findings, owners)
	s.sendToolJSON(id, groups)
}

func (s *server) toolFixPreview(id json.RawMessage, args json.RawMessage) {
	var p struct {
		Dir      string `json:"dir"`
		Analyzer string `json:"analyzer"`
	}
	if len(args) > 0 {
		json.Unmarshal(args, &p)
	}
	dir := p.Dir

	_, findings, ok := s.loadAndAnalyzeOrError(id, dir)
	if !ok {
		return
	}

	// Filter findings that have suggestions.
	type fixableFinding struct {
		analyzer.Finding
		HasFix bool `json:"hasFix"`
	}
	var fixable []fixableFinding
	for _, f := range findings {
		if p.Analyzer != "" && f.Analyzer != p.Analyzer {
			continue
		}
		if f.Suggestion != "" {
			fixable = append(fixable, fixableFinding{Finding: f, HasFix: true})
		}
	}

	data, _ := json.MarshalIndent(map[string]interface{}{
		"totalFindings":   len(findings),
		"fixableCount":    len(fixable),
		"fixableFindings": fixable,
		"analyzerFilter":  p.Analyzer,
	}, "", "  ")
	s.sendResponse(id, callToolResult{
		Content: []contentBlock{{Type: "text", Text: string(data)}},
	})
}

// ─── Helpers ───────────────────────────────────────────────────────────

// sendToolError sends an error response for a tool call.
func (s *server) sendToolError(id json.RawMessage, err error) {
	s.sendResponse(id, callToolResult{
		Content: []contentBlock{{Type: "text", Text: fmt.Sprintf("Error: %v", err)}},
		IsError: true,
	})
}

// sendToolJSON sends a JSON response for a tool call.
func (s *server) sendToolJSON(id json.RawMessage, v interface{}) {
	data, _ := json.MarshalIndent(v, "", "  ")
	s.sendResponse(id, callToolResult{
		Content: []contentBlock{{Type: "text", Text: string(data)}},
	})
}

// loadAndAnalyzeOrError loads the codebase, runs all analyzers, and returns
// the context and findings. On error, sends the error to the client and
// returns nil. This eliminates the repeated load+error pattern across tool handlers.
func (s *server) loadAndAnalyzeOrError(id json.RawMessage, dir string) (*analyzer.Context, []analyzer.Finding, bool) {
	ctx, findings, err := loadAndAnalyze(dir, []string{"./..."})
	if err != nil {
		s.sendToolError(id, err)
		return nil, nil, false
	}
	return ctx, findings, true
}

// parseDirArgs extracts the "dir" field from tool call arguments.
// Returns empty string if no dir field or empty args.
func parseDirArgs(args json.RawMessage) string {
	var p struct {
		Dir string `json:"dir"`
	}
	if len(args) > 0 {
		json.Unmarshal(args, &p)
	}
	return p.Dir
}

// parsePathArgs extracts "dir" and "path" fields from tool call arguments.
func parsePathArgs(args json.RawMessage) (dir, path string) {
	var p struct {
		Dir  string `json:"dir"`
		Path string `json:"path"`
	}
	if len(args) > 0 {
		json.Unmarshal(args, &p)
	}
	return p.Dir, p.Path
}

// parseDirBaseRefArgs extracts "dir" and "base_ref" fields, defaulting base_ref
// to "origin/main" when empty.
func parseDirBaseRefArgs(args json.RawMessage) (dir, baseRef string) {
	var p struct {
		Dir     string `json:"dir"`
		BaseRef string `json:"base_ref"`
	}
	if len(args) > 0 {
		json.Unmarshal(args, &p)
	}
	if p.BaseRef == "" {
		p.BaseRef = "origin/main"
	}
	return p.Dir, p.BaseRef
}

// loadAndAnalyze loads the codebase and runs all analyzers.
// Returns the analyzer context (for explain/trace) and all findings.
func loadAndAnalyze(dir string, patterns []string) (*analyzer.Context, []analyzer.Finding, error) {
	if len(patterns) == 0 {
		patterns = []string{"./..."}
	}

	result, err := loader.Load(loader.LoadConfig{
		Patterns: patterns,
		Dir:      dir,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("load codebase: %w", err)
	}

	ctx := &analyzer.Context{
		FSET:        result.FSET,
		Packages:    result.Packages,
		SSA:         result.SSA,
		SSAByPkg:    result.SSAByPkg,
		TypesByPkg:  result.TypesByPkg,
		SyntaxByPkg: result.SyntaxByPkg,
	}

	registry := analyzer.NewRegistry()
	var allFindings []analyzer.Finding
	for _, a := range registry.All() {
		findings, err := a.Analyze(ctx)
		if err != nil {
			continue
		}
		allFindings = append(allFindings, findings...)
	}

	return ctx, allFindings, nil
}

// runAnalyzersByName loads the codebase and runs only the named analyzers.
func runAnalyzersByName(dir string, names []string) ([]analyzer.Finding, error) {
	result, err := loader.Load(loader.LoadConfig{Patterns: []string{"./..."}, Dir: dir})
	if err != nil {
		return nil, fmt.Errorf("load codebase: %w", err)
	}

	ctx := &analyzer.Context{
		FSET:        result.FSET,
		Packages:    result.Packages,
		SSA:         result.SSA,
		SSAByPkg:    result.SSAByPkg,
		TypesByPkg:  result.TypesByPkg,
		SyntaxByPkg: result.SyntaxByPkg,
	}

	registry := analyzer.NewRegistry()
	selected := registry.Select(names)

	var allFindings []analyzer.Finding
	for _, a := range selected {
		findings, err := a.Analyze(ctx)
		if err != nil {
			continue
		}
		allFindings = append(allFindings, findings...)
	}

	return allFindings, nil
}

// fileExists checks whether the given path exists on disk.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// pkgHasSuffixStr checks if a package path ends with the given suffix at a path boundary.
func pkgHasSuffixStr(pkgPath, suffix string) bool {
	if strings.HasSuffix(pkgPath, suffix) {
		if len(pkgPath) == len(suffix) || pkgPath[len(pkgPath)-len(suffix)-1] == '/' {
			return true
		}
	}
	return false
}

// parseGoMod reads go.mod and returns the module name and Go version.
func parseGoMod(dir string) (moduleName, goVersion string) {
	goModPath := filepath.Join(dir, "go.mod")
	data, err := os.ReadFile(goModPath)
	if err != nil {
		return "", ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "module ") {
			moduleName = strings.TrimSpace(strings.TrimPrefix(line, "module "))
		}
		if strings.HasPrefix(line, "go ") {
			goVersion = strings.TrimSpace(strings.TrimPrefix(line, "go "))
		}
	}
	return moduleName, goVersion
}

// countGoModDeps counts the number of require directives in go.mod.
func countGoModDeps(dir string) int {
	goModPath := filepath.Join(dir, "go.mod")
	data, err := os.ReadFile(goModPath)
	if err != nil {
		return 0
	}
	count := 0
	inBlock := false
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "require (") {
			inBlock = true
			continue
		}
		if inBlock && trimmed == ")" {
			inBlock = false
			continue
		}
		if inBlock && trimmed != "" && !strings.HasPrefix(trimmed, "//") {
			count++
			continue
		}
		if strings.HasPrefix(trimmed, "require ") && !strings.HasSuffix(trimmed, "(") {
			count++
		}
	}
	return count
}

// getChangedFiles returns the list of files changed relative to the given git base ref.
func getChangedFiles(baseRef, dir string) ([]string, error) {
	cmd := execGitCommand("diff", "--name-only", baseRef+"...HEAD", dir)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git diff: %w", err)
	}

	var files []string
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			files = append(files, line)
		}
	}
	return files, nil
}

// execGitCommand creates a git command with the given args and working directory.
func execGitCommand(args ...string) *exec.Cmd {
	cmd := exec.Command("git", args[:len(args)-1]...)
	cmd.Dir = args[len(args)-1]
	return cmd
}

// Package mcp implements a minimal Model Context Protocol server for Gollaw.
// It exposes Gollaw's analysis capabilities as tools that AI agents can call.
// The protocol is implemented directly over JSON-RPC 2.0 with Content-Length framing.
package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"go/ast"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/dovocoder/gollaw/internal/analyzer"
	"github.com/dovocoder/gollaw/internal/audit"
	"github.com/dovocoder/gollaw/internal/baseline"
	"github.com/dovocoder/gollaw/internal/codeowners"
	"github.com/dovocoder/gollaw/internal/config"
	"github.com/dovocoder/gollaw/internal/coverage"
	"github.com/dovocoder/gollaw/internal/explain"
	"github.com/dovocoder/gollaw/internal/filescore"
	"github.com/dovocoder/gollaw/internal/guard"
	"github.com/dovocoder/gollaw/internal/loader"
	"github.com/dovocoder/gollaw/internal/publicapi"
	"github.com/dovocoder/gollaw/internal/reporter"
	"github.com/dovocoder/gollaw/internal/suppress"
	"github.com/dovocoder/gollaw/internal/trace"
	"github.com/dovocoder/gollaw/internal/xref"
)

const protocolVersion = "2024-11-05"

// mcpVersion is the MCP server version (mirrors cli.Version to avoid an import cycle).
const mcpVersion = "0.2.0"

// ServeMCP runs the MCP server loop over the given reader/writer (typically stdio).
func ServeMCP(in io.Reader, out io.Writer) error {
	s := &server{
		reader: bufio.NewReader(in),
		writer: out,
	}
	return s.run()
}

// ─── Server struct ─────────────────────────────────────────────────────

type server struct {
	reader  *bufio.Reader
	writer  io.Writer
	writeMu sync.Mutex
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

func (s *server) readMessage() ([]byte, error) {
	contentLength := 0
	for {
		line, err := s.reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		if strings.HasPrefix(line, "Content-Length:") {
			fmt.Sscanf(line, "Content-Length: %d", &contentLength)
		}
	}
	if contentLength == 0 {
		return nil, fmt.Errorf("missing Content-Length header")
	}
	buf := make([]byte, contentLength)
	_, err := io.ReadFull(s.reader, buf)
	return buf, err
}

func (s *server) writeMessage(data []byte) error {
	header := fmt.Sprintf("Content-Length: %d\r\n\r\n", len(data))
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if _, err := s.writer.Write([]byte(header)); err != nil {
		return err
	}
	_, err := s.writer.Write(data)
	return err
}

func (s *server) sendResponse(id json.RawMessage, result interface{}) {
	resp := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      json.RawMessage(id),
		"result":  result,
	}
	data, _ := json.Marshal(resp)
	s.writeMessage(data)
}

func (s *server) sendError(id json.RawMessage, code int, message string) {
	resp := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      json.RawMessage(id),
		"error": map[string]interface{}{
			"code":    code,
			"message": message,
		},
	}
	data, _ := json.Marshal(resp)
	s.writeMessage(data)
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

func (s *server) handleToolsList(id json.RawMessage) {
	tools := []toolDef{
		{
			Name:        "gollaw_analyze",
			Description: "Run Gollaw analysis on a Go codebase directory. Returns all findings as JSON.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"dir": map[string]interface{}{
						"type":        "string",
						"description": "Directory to analyze (default: current directory)",
					},
					"patterns": map[string]interface{}{
						"type":        "array",
						"items":       map[string]interface{}{"type": "string"},
						"description": "Go package patterns (default: [\"./...\"])",
					},
				},
			},
		},
		{
			Name:        "gollaw_list_analyzers",
			Description: "List all available Gollaw analyzers with their names and descriptions.",
			InputSchema: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
		{
			Name:        "gollaw_explain",
			Description: "Explain why a Go symbol (function, type, method) is unused or dead. Shows the call chain and reason.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"dir": map[string]interface{}{
						"type":        "string",
						"description": "Directory containing the Go codebase",
					},
					"symbol": map[string]interface{}{
						"type":        "string",
						"description": "Symbol name (e.g. \"MyFunc\", \"Type.Method\", \"pkg.Func\")",
					},
				},
				"required": []string{"dir", "symbol"},
			},
		},
		{
			Name:        "gollaw_trace",
			Description: "Trace callers or callees of a Go symbol. Returns all call chains as JSON.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"dir": map[string]interface{}{
						"type":        "string",
						"description": "Directory containing the Go codebase",
					},
					"symbol": map[string]interface{}{
						"type":        "string",
						"description": "Symbol name to trace",
					},
					"direction": map[string]interface{}{
						"type":        "string",
						"enum":        []string{"callers", "callees"},
						"description": "Trace direction (default: callers)",
					},
					"maxDepth": map[string]interface{}{
						"type":        "number",
						"description": "Maximum trace depth (default: 10)",
					},
				},
				"required": []string{"dir", "symbol"},
			},
		},
		{
			Name:        "gollaw_health",
			Description: "Get the health score (0-100) for a Go codebase directory. Includes grade and per-category breakdown.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"dir": map[string]interface{}{
						"type":        "string",
						"description": "Directory to score (default: current directory)",
					},
				},
			},
		},
		{
			Name:        "gollaw_audit",
			Description: "Run a PR audit: analyze changed files vs a git base ref, attribute findings as introduced vs pre-existing, and give a pass/warn/fail verdict.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"dir": map[string]interface{}{
						"type":        "string",
						"description": "Directory containing the Go codebase (default: current directory)",
					},
					"base_ref": map[string]interface{}{
						"type":        "string",
						"description": "Git base ref to diff against (default: origin/main)",
					},
				},
			},
		},
		{
			Name:        "gollaw_guard",
			Description: "Get a pre-edit architecture guard report for a file: which rules apply and whether the file's package currently violates any rule.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"file_path": map[string]interface{}{
						"type":        "string",
						"description": "Path to the file to guard",
					},
					"dir": map[string]interface{}{
						"type":        "string",
						"description": "Directory containing the Go codebase (default: current directory)",
					},
					"rules": map[string]interface{}{
						"type":        "array",
						"items":       map[string]interface{}{"type": "string"},
						"description": "Architecture rules in \"package must not import other\" format (optional; uses config if absent)",
					},
				},
				"required": []string{"file_path"},
			},
		},
		{
			Name:        "gollaw_baseline_save",
			Description: "Save the current set of findings as a baseline snapshot to .gollaw/baseline.json.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"dir": map[string]interface{}{
						"type":        "string",
						"description": "Directory containing the Go codebase (default: current directory)",
					},
				},
			},
		},
		{
			Name:        "gollaw_baseline_diff",
			Description: "Compare current findings against the saved baseline and return only new findings.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"dir": map[string]interface{}{
						"type":        "string",
						"description": "Directory containing the Go codebase (default: current directory)",
					},
				},
			},
		},
		{
			Name:        "gollaw_public_api",
			Description: "Analyze the public API surface: classify exports as confirmed public, accidental, or unused.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"dir": map[string]interface{}{
						"type":        "string",
						"description": "Directory containing the Go codebase (default: current directory)",
					},
				},
			},
		},
		{
			Name:        "gollaw_coverage",
			Description: "Analyze test coverage gaps: find functions that lack tests.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"dir": map[string]interface{}{
						"type":        "string",
						"description": "Directory containing the Go codebase (default: current directory)",
					},
				},
			},
		},
		{
			Name:        "gollaw_file_scores",
			Description: "Compute per-file health scores (0-100) based on findings attributed to each file.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"dir": map[string]interface{}{
						"type":        "string",
						"description": "Directory containing the Go codebase (default: current directory)",
					},
				},
			},
		},
		{
			Name:        "gollaw_xref",
			Description: "Cross-reference findings from multiple analyzers to find overlapping issues (e.g. duplicate + dead code).",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"dir": map[string]interface{}{
						"type":        "string",
						"description": "Directory containing the Go codebase (default: current directory)",
					},
				},
			},
		},
		{
			Name:        "gollaw_dupes",
			Description: "Find duplicate code only (runs just the duplication analyzer).",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"dir": map[string]interface{}{
						"type":        "string",
						"description": "Directory containing the Go codebase (default: current directory)",
					},
				},
			},
		},
		{
			Name:        "gollaw_security",
			Description: "Find security issues only (runs just the security analyzer).",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"dir": map[string]interface{}{
						"type":        "string",
						"description": "Directory containing the Go codebase (default: current directory)",
					},
				},
			},
		},
		{
			Name:        "gollaw_impact",
			Description: "Get an impact report: counts of findings by severity, category, and analyzer.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"dir": map[string]interface{}{
						"type":        "string",
						"description": "Directory containing the Go codebase (default: current directory)",
					},
				},
			},
		},
		{
			Name:        "gollaw_inspect",
			Description: "Inspect a file or symbol: returns file identity, findings in file, health score, and call chain if the target is a symbol.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"target": map[string]interface{}{
						"type":        "string",
						"description": "File path or symbol name to inspect",
					},
					"dir": map[string]interface{}{
						"type":        "string",
						"description": "Directory containing the Go codebase (default: current directory)",
					},
				},
				"required": []string{"target"},
			},
		},
		{
			Name:        "gollaw_list_boundaries",
			Description: "List all packages and which architecture rules apply to each.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"dir": map[string]interface{}{
						"type":        "string",
						"description": "Directory containing the Go codebase (default: current directory)",
					},
				},
			},
		},
		{
			Name:        "gollaw_project_info",
			Description: "Get project info: module name, Go version, package count, file count, function count, type count, and dependency count.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"dir": map[string]interface{}{
						"type":        "string",
						"description": "Directory containing the Go codebase (default: current directory)",
					},
				},
			},
		},
		{
			Name:        "gollaw_check_changed",
			Description: "Analyze only changed files (git diff against base ref) and return findings from those files.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"dir": map[string]interface{}{
						"type":        "string",
						"description": "Directory containing the Go codebase (default: current directory)",
					},
					"base_ref": map[string]interface{}{
						"type":        "string",
						"description": "Git base ref to diff against (default: origin/main)",
					},
				},
			},
		},
		{
			Name:        "gollaw_suppress",
			Description: "Find stale suppression comments that no longer match any finding.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"dir": map[string]interface{}{
						"type":        "string",
						"description": "Directory containing the Go codebase (default: current directory)",
					},
				},
			},
		},
		{
			Name:        "gollaw_owners",
			Description: "Group findings by CODEOWNERS: maps each finding to its responsible owners.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"dir": map[string]interface{}{
						"type":        "string",
						"description": "Directory containing the Go codebase (default: current directory)",
					},
				},
			},
		},
		{
			Name:        "gollaw_fix_preview",
			Description: "Preview auto-fixable findings: lists findings that have suggestions, optionally filtered by analyzer.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"dir": map[string]interface{}{
						"type":        "string",
						"description": "Directory containing the Go codebase (default: current directory)",
					},
					"analyzer": map[string]interface{}{
						"type":        "string",
						"description": "Filter to a specific analyzer name (optional)",
					},
				},
			},
		},
	}
	s.sendResponse(id, toolsListResult{Tools: tools})
}

func (s *server) handleToolsCall(id json.RawMessage, params json.RawMessage) {
	var p callToolParams
	if err := json.Unmarshal(params, &p); err != nil {
		s.sendError(id, -32602, "invalid tools/call params")
		return
	}

	switch p.Name {
	case "gollaw_analyze":
		s.toolAnalyze(id, p.Arguments)
	case "gollaw_list_analyzers":
		s.toolListAnalyzers(id)
	case "gollaw_explain":
		s.toolExplain(id, p.Arguments)
	case "gollaw_trace":
		s.toolTrace(id, p.Arguments)
	case "gollaw_health":
		s.toolHealth(id, p.Arguments)
	case "gollaw_audit":
		s.toolAudit(id, p.Arguments)
	case "gollaw_guard":
		s.toolGuard(id, p.Arguments)
	case "gollaw_baseline_save":
		s.toolBaselineSave(id, p.Arguments)
	case "gollaw_baseline_diff":
		s.toolBaselineDiff(id, p.Arguments)
	case "gollaw_public_api":
		s.toolPublicAPI(id, p.Arguments)
	case "gollaw_coverage":
		s.toolCoverage(id, p.Arguments)
	case "gollaw_file_scores":
		s.toolFileScores(id, p.Arguments)
	case "gollaw_xref":
		s.toolXRef(id, p.Arguments)
	case "gollaw_dupes":
		s.toolDupes(id, p.Arguments)
	case "gollaw_security":
		s.toolSecurity(id, p.Arguments)
	case "gollaw_impact":
		s.toolImpact(id, p.Arguments)
	case "gollaw_inspect":
		s.toolInspect(id, p.Arguments)
	case "gollaw_list_boundaries":
		s.toolListBoundaries(id, p.Arguments)
	case "gollaw_project_info":
		s.toolProjectInfo(id, p.Arguments)
	case "gollaw_check_changed":
		s.toolCheckChanged(id, p.Arguments)
	case "gollaw_suppress":
		s.toolSuppress(id, p.Arguments)
	case "gollaw_owners":
		s.toolOwners(id, p.Arguments)
	case "gollaw_fix_preview":
		s.toolFixPreview(id, p.Arguments)
	default:
		s.sendError(id, -32602, fmt.Sprintf("unknown tool: %s", p.Name))
	}
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

	ctx, findings, err := loadAndAnalyze(p.Dir, p.Patterns)
	if err != nil {
		s.sendResponse(id, callToolResult{
			Content: []contentBlock{{Type: "text", Text: fmt.Sprintf("Error: %v", err)}},
			IsError: true,
		})
		return
	}
	_ = ctx

	// Build a report.
	stats := reporter.CodebaseStats{}
	result, _ := loader.Load(loader.LoadConfig{Patterns: p.Patterns, Dir: p.Dir})
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

	data, _ := json.MarshalIndent(rep, "", "  ")
	s.sendResponse(id, callToolResult{
		Content: []contentBlock{{Type: "text", Text: string(data)}},
	})
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
	data, _ := json.MarshalIndent(list, "", "  ")
	s.sendResponse(id, callToolResult{
		Content: []contentBlock{{Type: "text", Text: string(data)}},
	})
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

	ctx, _, err := loadAndAnalyze(p.Dir, []string{"./..."})
	if err != nil {
		s.sendResponse(id, callToolResult{
			Content: []contentBlock{{Type: "text", Text: fmt.Sprintf("Error: %v", err)}},
			IsError: true,
		})
		return
	}

	expl, err := explain.ExplainUnused(ctx, p.Symbol)
	if err != nil {
		s.sendResponse(id, callToolResult{
			Content: []contentBlock{{Type: "text", Text: fmt.Sprintf("Error: %v", err)}},
			IsError: true,
		})
		return
	}

	data, _ := json.MarshalIndent(expl, "", "  ")
	s.sendResponse(id, callToolResult{
		Content: []contentBlock{{Type: "text", Text: string(data)}},
	})
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

	ctx, _, err := loadAndAnalyze(p.Dir, []string{"./..."})
	if err != nil {
		s.sendResponse(id, callToolResult{
			Content: []contentBlock{{Type: "text", Text: fmt.Sprintf("Error: %v", err)}},
			IsError: true,
		})
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
		s.sendResponse(id, callToolResult{
			Content: []contentBlock{{Type: "text", Text: fmt.Sprintf("Error: %v", err)}},
			IsError: true,
		})
		return
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	s.sendResponse(id, callToolResult{
		Content: []contentBlock{{Type: "text", Text: string(data)}},
	})
}

func (s *server) toolHealth(id json.RawMessage, args json.RawMessage) {
	var p struct {
		Dir string `json:"dir"`
	}
	if len(args) > 0 {
		json.Unmarshal(args, &p)
	}

	_, findings, err := loadAndAnalyze(p.Dir, []string{"./..."})
	if err != nil {
		s.sendResponse(id, callToolResult{
			Content: []contentBlock{{Type: "text", Text: fmt.Sprintf("Error: %v", err)}},
			IsError: true,
		})
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

	ctx, findings, err := loadAndAnalyze(p.Dir, []string{"./..."})
	if err != nil {
		s.sendResponse(id, callToolResult{
			Content: []contentBlock{{Type: "text", Text: fmt.Sprintf("Error: %v", err)}},
			IsError: true,
		})
		return
	}

	auditRep, err := audit.RunAudit(ctx, p.BaseRef, findings, p.Dir)
	if err != nil {
		s.sendResponse(id, callToolResult{
			Content: []contentBlock{{Type: "text", Text: fmt.Sprintf("Error: %v", err)}},
			IsError: true,
		})
		return
	}

	data, _ := json.MarshalIndent(auditRep, "", "  ")
	s.sendResponse(id, callToolResult{
		Content: []contentBlock{{Type: "text", Text: string(data)}},
	})
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

	// Parse architecture rules.
	var archRules []analyzer.Rule
	for _, r := range p.Rules {
		parts := strings.SplitN(r, " must not import ", 2)
		if len(parts) == 2 {
			archRules = append(archRules, analyzer.Rule{
				Package:    strings.TrimSpace(parts[0]),
				MustNotUse: strings.TrimSpace(parts[1]),
			})
		}
	}

	// Load config rules if no explicit rules were given.
	if len(archRules) == 0 {
		configPath := config.FindConfig(p.Dir)
		if configPath != "" {
			if fc, err := config.Load(configPath); err == nil {
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
	}

	result, err := loader.Load(loader.LoadConfig{Patterns: []string{"./..."}, Dir: p.Dir})
	if err != nil {
		s.sendResponse(id, callToolResult{
			Content: []contentBlock{{Type: "text", Text: fmt.Sprintf("Error: %v", err)}},
			IsError: true,
		})
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
		s.sendResponse(id, callToolResult{
			Content: []contentBlock{{Type: "text", Text: fmt.Sprintf("Error: %v", err)}},
			IsError: true,
		})
		return
	}

	data, _ := json.MarshalIndent(guardRep, "", "  ")
	s.sendResponse(id, callToolResult{
		Content: []contentBlock{{Type: "text", Text: string(data)}},
	})
}

func (s *server) toolBaselineSave(id json.RawMessage, args json.RawMessage) {
	var p struct {
		Dir string `json:"dir"`
	}
	if len(args) > 0 {
		json.Unmarshal(args, &p)
	}

	_, findings, err := loadAndAnalyze(p.Dir, []string{"./..."})
	if err != nil {
		s.sendResponse(id, callToolResult{
			Content: []contentBlock{{Type: "text", Text: fmt.Sprintf("Error: %v", err)}},
			IsError: true,
		})
		return
	}

	if err := baseline.Save(p.Dir, findings); err != nil {
		s.sendResponse(id, callToolResult{
			Content: []contentBlock{{Type: "text", Text: fmt.Sprintf("Error: %v", err)}},
			IsError: true,
		})
		return
	}

	data, _ := json.MarshalIndent(map[string]interface{}{
		"savedFindings": len(findings),
		"path":          filepath.Join(p.Dir, ".gollaw", "baseline.json"),
	}, "", "  ")
	s.sendResponse(id, callToolResult{
		Content: []contentBlock{{Type: "text", Text: string(data)}},
	})
}

func (s *server) toolBaselineDiff(id json.RawMessage, args json.RawMessage) {
	var p struct {
		Dir string `json:"dir"`
	}
	if len(args) > 0 {
		json.Unmarshal(args, &p)
	}

	_, findings, err := loadAndAnalyze(p.Dir, []string{"./..."})
	if err != nil {
		s.sendResponse(id, callToolResult{
			Content: []contentBlock{{Type: "text", Text: fmt.Sprintf("Error: %v", err)}},
			IsError: true,
		})
		return
	}

	bl, err := baseline.Load(p.Dir)
	if err != nil {
		s.sendResponse(id, callToolResult{
			Content: []contentBlock{{Type: "text", Text: fmt.Sprintf("Error: %v", err)}},
			IsError: true,
		})
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
	var p struct {
		Dir string `json:"dir"`
	}
	if len(args) > 0 {
		json.Unmarshal(args, &p)
	}

	ctx, _, err := loadAndAnalyze(p.Dir, []string{"./..."})
	if err != nil {
		s.sendResponse(id, callToolResult{
			Content: []contentBlock{{Type: "text", Text: fmt.Sprintf("Error: %v", err)}},
			IsError: true,
		})
		return
	}

	apiRep, err := publicapi.AnalyzePublicAPI(ctx)
	if err != nil {
		s.sendResponse(id, callToolResult{
			Content: []contentBlock{{Type: "text", Text: fmt.Sprintf("Error: %v", err)}},
			IsError: true,
		})
		return
	}

	data, _ := json.MarshalIndent(apiRep, "", "  ")
	s.sendResponse(id, callToolResult{
		Content: []contentBlock{{Type: "text", Text: string(data)}},
	})
}

func (s *server) toolCoverage(id json.RawMessage, args json.RawMessage) {
	var p struct {
		Dir string `json:"dir"`
	}
	if len(args) > 0 {
		json.Unmarshal(args, &p)
	}

	ctx, _, err := loadAndAnalyze(p.Dir, []string{"./..."})
	if err != nil {
		s.sendResponse(id, callToolResult{
			Content: []contentBlock{{Type: "text", Text: fmt.Sprintf("Error: %v", err)}},
			IsError: true,
		})
		return
	}

	covRep, err := coverage.AnalyzeCoverage(ctx)
	if err != nil {
		s.sendResponse(id, callToolResult{
			Content: []contentBlock{{Type: "text", Text: fmt.Sprintf("Error: %v", err)}},
			IsError: true,
		})
		return
	}

	data, _ := json.MarshalIndent(covRep, "", "  ")
	s.sendResponse(id, callToolResult{
		Content: []contentBlock{{Type: "text", Text: string(data)}},
	})
}

func (s *server) toolFileScores(id json.RawMessage, args json.RawMessage) {
	var p struct {
		Dir string `json:"dir"`
	}
	if len(args) > 0 {
		json.Unmarshal(args, &p)
	}

	_, findings, err := loadAndAnalyze(p.Dir, []string{"./..."})
	if err != nil {
		s.sendResponse(id, callToolResult{
			Content: []contentBlock{{Type: "text", Text: fmt.Sprintf("Error: %v", err)}},
			IsError: true,
		})
		return
	}

	scores := filescore.ScoreFiles(findings, nil)
	data, _ := json.MarshalIndent(scores, "", "  ")
	s.sendResponse(id, callToolResult{
		Content: []contentBlock{{Type: "text", Text: string(data)}},
	})
}

func (s *server) toolXRef(id json.RawMessage, args json.RawMessage) {
	var p struct {
		Dir string `json:"dir"`
	}
	if len(args) > 0 {
		json.Unmarshal(args, &p)
	}

	_, findings, err := loadAndAnalyze(p.Dir, []string{"./..."})
	if err != nil {
		s.sendResponse(id, callToolResult{
			Content: []contentBlock{{Type: "text", Text: fmt.Sprintf("Error: %v", err)}},
			IsError: true,
		})
		return
	}

	combined := xref.CrossReference(findings)
	data, _ := json.MarshalIndent(combined, "", "  ")
	s.sendResponse(id, callToolResult{
		Content: []contentBlock{{Type: "text", Text: string(data)}},
	})
}

func (s *server) toolDupes(id json.RawMessage, args json.RawMessage) {
	var p struct {
		Dir string `json:"dir"`
	}
	if len(args) > 0 {
		json.Unmarshal(args, &p)
	}

	findings, err := runAnalyzersByName(p.Dir, []string{"duplication"})
	if err != nil {
		s.sendResponse(id, callToolResult{
			Content: []contentBlock{{Type: "text", Text: fmt.Sprintf("Error: %v", err)}},
			IsError: true,
		})
		return
	}

	data, _ := json.MarshalIndent(findings, "", "  ")
	s.sendResponse(id, callToolResult{
		Content: []contentBlock{{Type: "text", Text: string(data)}},
	})
}

func (s *server) toolSecurity(id json.RawMessage, args json.RawMessage) {
	var p struct {
		Dir string `json:"dir"`
	}
	if len(args) > 0 {
		json.Unmarshal(args, &p)
	}

	findings, err := runAnalyzersByName(p.Dir, []string{"security"})
	if err != nil {
		s.sendResponse(id, callToolResult{
			Content: []contentBlock{{Type: "text", Text: fmt.Sprintf("Error: %v", err)}},
			IsError: true,
		})
		return
	}

	data, _ := json.MarshalIndent(findings, "", "  ")
	s.sendResponse(id, callToolResult{
		Content: []contentBlock{{Type: "text", Text: string(data)}},
	})
}

func (s *server) toolImpact(id json.RawMessage, args json.RawMessage) {
	var p struct {
		Dir string `json:"dir"`
	}
	if len(args) > 0 {
		json.Unmarshal(args, &p)
	}

	_, findings, err := loadAndAnalyze(p.Dir, []string{"./..."})
	if err != nil {
		s.sendResponse(id, callToolResult{
			Content: []contentBlock{{Type: "text", Text: fmt.Sprintf("Error: %v", err)}},
			IsError: true,
		})
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

	ctx, findings, err := loadAndAnalyze(p.Dir, []string{"./..."})
	if err != nil {
		s.sendResponse(id, callToolResult{
			Content: []contentBlock{{Type: "text", Text: fmt.Sprintf("Error: %v", err)}},
			IsError: true,
		})
		return
	}

	// Check if target looks like a file path.
	isFile := strings.HasSuffix(p.Target, ".go") || filepath.Ext(p.Target) != ""
	if isFile {
		result := s.inspectFile(ctx, findings, p.Target)
		data, _ := json.MarshalIndent(result, "", "  ")
		s.sendResponse(id, callToolResult{
			Content: []contentBlock{{Type: "text", Text: string(data)}},
		})
		return
	}

	// Otherwise treat target as a symbol name.
	result := s.inspectSymbol(ctx, findings, p.Target)
	data, _ := json.MarshalIndent(result, "", "  ")
	s.sendResponse(id, callToolResult{
		Content: []contentBlock{{Type: "text", Text: string(data)}},
	})
}

func (s *server) inspectFile(ctx *analyzer.Context, findings []analyzer.Finding, target string) map[string]interface{} {
	absTarget, _ := filepath.Abs(target)

	// Find findings in this file.
	var fileFindings []analyzer.Finding
	for _, f := range findings {
		if f.File == target || f.File == absTarget {
			fileFindings = append(fileFindings, f)
		}
	}

	// Determine the package this file belongs to.
	pkgPath := ""
	for _, pkg := range ctx.Packages {
		for _, f := range pkg.GoFiles {
			absF, _ := filepath.Abs(f)
			if absF == absTarget || f == target {
				pkgPath = pkg.PkgPath
				break
			}
		}
		if pkgPath != "" {
			break
		}
	}

	// Health score for this file.
	scores := filescore.ScoreFiles(fileFindings, nil)
	var score interface{}
	if len(scores) > 0 {
		score = scores[0]
	} else {
		score = map[string]interface{}{
			"file":         target,
			"score":        100,
			"grade":        "A",
			"findingCount": 0,
		}
	}

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
	var p struct {
		Dir string `json:"dir"`
	}
	if len(args) > 0 {
		json.Unmarshal(args, &p)
	}

	// Load config for rules.
	var archRules []analyzer.Rule
	configPath := config.FindConfig(p.Dir)
	if configPath != "" {
		if fc, err := config.Load(configPath); err == nil {
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

	result, err := loader.Load(loader.LoadConfig{Patterns: []string{"./..."}, Dir: p.Dir})
	if err != nil {
		s.sendResponse(id, callToolResult{
			Content: []contentBlock{{Type: "text", Text: fmt.Sprintf("Error: %v", err)}},
			IsError: true,
		})
		return
	}

	type boundaryInfo struct {
		Package    string         `json:"package"`
		Imports    []string       `json:"imports"`
		Rules      []analyzer.Rule `json:"rules"`
	}
	var boundaries []boundaryInfo

	for _, pkg := range result.Packages {
		if pkg.Types == nil {
			continue
		}
		var imports []string
		for _, imp := range pkg.Imports {
			if imp != nil {
				imports = append(imports, imp.PkgPath)
			}
		}
		sort.Strings(imports)

		var applicableRules []analyzer.Rule
		for _, rule := range archRules {
			if pkgHasSuffixStr(pkg.PkgPath, rule.Package) || pkgHasSuffixStr(pkg.PkgPath, rule.MustNotUse) {
				applicableRules = append(applicableRules, rule)
			}
		}

		boundaries = append(boundaries, boundaryInfo{
			Package: pkg.PkgPath,
			Imports: imports,
			Rules:   applicableRules,
		})
	}

	data, _ := json.MarshalIndent(map[string]interface{}{
		"totalRules":     len(archRules),
		"totalPackages":  len(boundaries),
		"boundaries":     boundaries,
	}, "", "  ")
	s.sendResponse(id, callToolResult{
		Content: []contentBlock{{Type: "text", Text: string(data)}},
	})
}

func (s *server) toolProjectInfo(id json.RawMessage, args json.RawMessage) {
	var p struct {
		Dir string `json:"dir"`
	}
	if len(args) > 0 {
		json.Unmarshal(args, &p)
	}

	result, err := loader.Load(loader.LoadConfig{Patterns: []string{"./..."}, Dir: p.Dir})
	if err != nil {
		s.sendResponse(id, callToolResult{
			Content: []contentBlock{{Type: "text", Text: fmt.Sprintf("Error: %v", err)}},
			IsError: true,
		})
		return
	}

	// Parse go.mod for module name and Go version.
	moduleName, goVersion := parseGoMod(p.Dir)

	// Count unique dependencies from go.mod.
	depCount := countGoModDeps(p.Dir)

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

	data, _ := json.MarshalIndent(info, "", "  ")
	s.sendResponse(id, callToolResult{
		Content: []contentBlock{{Type: "text", Text: string(data)}},
	})
}

func (s *server) toolCheckChanged(id json.RawMessage, args json.RawMessage) {
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

	_, findings, err := loadAndAnalyze(p.Dir, []string{"./..."})
	if err != nil {
		s.sendResponse(id, callToolResult{
			Content: []contentBlock{{Type: "text", Text: fmt.Sprintf("Error: %v", err)}},
			IsError: true,
		})
		return
	}

	// Get changed files via git.
	changedFiles, err := getChangedFiles(p.BaseRef, p.Dir)
	if err != nil {
		s.sendResponse(id, callToolResult{
			Content: []contentBlock{{Type: "text", Text: fmt.Sprintf("Error: %v", err)}},
			IsError: true,
		})
		return
	}

	// Build a set of changed files (both relative and absolute forms).
	changedSet := make(map[string]bool)
	for _, f := range changedFiles {
		changedSet[f] = true
		abs, _ := filepath.Abs(filepath.Join(p.Dir, f))
		changedSet[abs] = true
		changedSet[filepath.Base(f)] = true
	}

	var changedFindings []analyzer.Finding
	for _, f := range findings {
		if changedSet[f.File] {
			changedFindings = append(changedFindings, f)
		}
	}

	data, _ := json.MarshalIndent(map[string]interface{}{
		"baseRef":         p.BaseRef,
		"changedFiles":    changedFiles,
		"changedFileCount": len(changedFiles),
		"findings":        changedFindings,
		"findingCount":    len(changedFindings),
	}, "", "  ")
	s.sendResponse(id, callToolResult{
		Content: []contentBlock{{Type: "text", Text: string(data)}},
	})
}

func (s *server) toolSuppress(id json.RawMessage, args json.RawMessage) {
	var p struct {
		Dir string `json:"dir"`
	}
	if len(args) > 0 {
		json.Unmarshal(args, &p)
	}

	ctx, findings, err := loadAndAnalyze(p.Dir, []string{"./..."})
	if err != nil {
		s.sendResponse(id, callToolResult{
			Content: []contentBlock{{Type: "text", Text: fmt.Sprintf("Error: %v", err)}},
			IsError: true,
		})
		return
	}

	// Parse suppressions from all loaded source files.
	var allFiles []*ast.File
	for _, files := range ctx.SyntaxByPkg {
		allFiles = append(allFiles, files...)
	}
	sup, err := suppress.ParseSuppressions(ctx.FSET, allFiles)
	if err != nil {
		s.sendResponse(id, callToolResult{
			Content: []contentBlock{{Type: "text", Text: fmt.Sprintf("Error: %v", err)}},
			IsError: true,
		})
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
	var p struct {
		Dir string `json:"dir"`
	}
	if len(args) > 0 {
		json.Unmarshal(args, &p)
	}

	_, findings, err := loadAndAnalyze(p.Dir, []string{"./..."})
	if err != nil {
		s.sendResponse(id, callToolResult{
			Content: []contentBlock{{Type: "text", Text: fmt.Sprintf("Error: %v", err)}},
			IsError: true,
		})
		return
	}

	ownersFile, err := codeowners.FindCodeOwnersFile(p.Dir)
	if err != nil {
		s.sendResponse(id, callToolResult{
			Content: []contentBlock{{Type: "text", Text: fmt.Sprintf("Error: %v", err)}},
			IsError: true,
		})
		return
	}

	owners, err := codeowners.Parse(ownersFile)
	if err != nil {
		s.sendResponse(id, callToolResult{
			Content: []contentBlock{{Type: "text", Text: fmt.Sprintf("Error: %v", err)}},
			IsError: true,
		})
		return
	}

	groups := codeowners.GroupByOwner(findings, owners)
	data, _ := json.MarshalIndent(groups, "", "  ")
	s.sendResponse(id, callToolResult{
		Content: []contentBlock{{Type: "text", Text: string(data)}},
	})
}

func (s *server) toolFixPreview(id json.RawMessage, args json.RawMessage) {
	var p struct {
		Dir      string `json:"dir"`
		Analyzer string `json:"analyzer"`
	}
	if len(args) > 0 {
		json.Unmarshal(args, &p)
	}

	_, findings, err := loadAndAnalyze(p.Dir, []string{"./..."})
	if err != nil {
		s.sendResponse(id, callToolResult{
			Content: []contentBlock{{Type: "text", Text: fmt.Sprintf("Error: %v", err)}},
			IsError: true,
		})
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

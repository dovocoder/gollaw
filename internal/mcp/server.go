// Package mcp implements a minimal Model Context Protocol server for Gollaw.
// It exposes Gollaw's analysis capabilities as tools that AI agents can call.
// The protocol is implemented directly over JSON-RPC 2.0 with Content-Length framing.
package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/dovocoder/gollaw/internal/analyzer"
	"github.com/dovocoder/gollaw/internal/explain"
	"github.com/dovocoder/gollaw/internal/loader"
	"github.com/dovocoder/gollaw/internal/reporter"
	"github.com/dovocoder/gollaw/internal/trace"
)

const protocolVersion = "2024-11-05"

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
			Version: "0.1.0",
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

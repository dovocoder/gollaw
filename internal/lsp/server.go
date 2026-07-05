// Package lsp implements a minimal Language Server Protocol server for Gollaw.
// It provides live diagnostics in any LSP-compatible editor (VS Code, Neovim, etc).
// The protocol is implemented directly over JSON-RPC 2.0 with Content-Length framing.
package lsp

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/dovocoder/gollaw/internal/analyzer"
	"github.com/dovocoder/gollaw/internal/jsonrpc"
	"github.com/dovocoder/gollaw/internal/loader"
)

// ServeLSP runs the LSP server loop over the given reader/writer (typically stdio).
func ServeLSP(in io.Reader, out io.Writer) error {
	s := &server{
		conn:     jsonrpc.NewConn(in, out),
		docs:     make(map[string]*document),
		logger:   log.New(io.Discard, "", 0), // suppress by default
	}
	return s.run()
}

// ─── Server struct ─────────────────────────────────────────────────────

type server struct {
	conn     *jsonrpc.Conn
	docs     map[string]*document
	rootPath string
	timer    *time.Timer
	timerMu  sync.Mutex
	logger   *log.Logger
}

type document struct {
	text    string
	version int
}

// ─── LSP types ────────────────────────────────────────────────────────

type rpcMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type initializeParams struct {
	RootURI string `json:"rootUri"`
	// RootPath is deprecated in favor of RootURI but widely used.
	RootPath string `json:"rootPath"`
}

type initializeResult struct {
	Capabilities serverCapabilities `json:"capabilities"`
	ServerInfo    serverInfo        `json:"serverInfo"`
}

type serverCapabilities struct {
	TextDocumentSync int  `json:"textDocumentSync"` // 1 = Full
	HoverProvider    bool `json:"hoverProvider"`
}

type serverInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type didOpenParams struct {
	TextDocument textDocumentItem `json:"textDocument"`
}

type textDocumentItem struct {
	URI     string `json:"uri"`
	Text    string `json:"text"`
	Version int    `json:"version"`
}

type didChangeParams struct {
	TextDocument   versionedTextDocumentIdentifier `json:"textDocument"`
	ContentChanges []textDocumentChange            `json:"contentChanges"`
}

type versionedTextDocumentIdentifier struct {
	URI     string `json:"uri"`
	Version int    `json:"version"`
}

type textDocumentChange struct {
	Range *textRange `json:"range,omitempty"`
	Text  string     `json:"text"`
}

type hoverParams struct {
	TextDocument textDocumentIdentifier `json:"textDocument"`
	Position     position               `json:"position"`
}

type textDocumentIdentifier struct {
	URI string `json:"uri"`
}

type position struct {
	Line      int `json:"line"`
	Character int `json:"character"`
}

type textRange struct {
	Start position `json:"start"`
	End   position `json:"end"`
}

type diagnostic struct {
	Range    textRange `json:"range"`
	Severity int       `json:"severity"`
	Source   string    `json:"source"`
	Message  string    `json:"message"`
	Code     string    `json:"code,omitempty"`
}

type publishDiagnosticsParams struct {
	URI         string       `json:"uri"`
	Diagnostics []diagnostic `json:"diagnostics"`
}

type hoverResult struct {
	Contents markupContent `json:"contents"`
}

type markupContent struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

// ─── Main loop ────────────────────────────────────────────────────────

// lspHandler represents a dispatch entry for an LSP method.
type lspHandler struct {
	// isExit causes the run loop to return immediately.
	isExit bool
	// handle dispatches the message. For requests, the id and params are passed.
	// For notifications, only the params are meaningful (id is empty).
	handle func(s *server, id json.RawMessage, params json.RawMessage)
}

// lspDispatch maps method names to their handlers.
var lspDispatch = map[string]lspHandler{
	"initialize": {
		handle: func(s *server, id, params json.RawMessage) { s.handleInitialize(id, params) },
	},
	"initialized":              {handle: func(s *server, _, _ json.RawMessage) {}},
	"shutdown":                 {handle: func(s *server, id, _ json.RawMessage) { s.sendResponse(id, nil) }},
	"exit":                     {isExit: true, handle: func(s *server, _, _ json.RawMessage) {}},
	"textDocument/didOpen":     {handle: func(s *server, _, params json.RawMessage) { s.handleDidOpen(params) }},
	"textDocument/didChange":   {handle: func(s *server, _, params json.RawMessage) { s.handleDidChange(params) }},
	"textDocument/didClose":    {handle: func(s *server, _, params json.RawMessage) { s.handleDidClose(params) }},
	"textDocument/hover": {
		handle: func(s *server, id, params json.RawMessage) { s.handleHover(id, params) },
	},
}

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
			s.logger.Printf("unmarshal error: %v", err)
			continue
		}

		if h, ok := lspDispatch[rpc.Method]; ok {
			h.handle(s, rpc.ID, rpc.Params)
			if h.isExit {
				return nil
			}
			continue
		}

		// Unknown method — respond with error only for requests.
		if len(rpc.ID) > 0 {
			s.sendError(rpc.ID, -32601, fmt.Sprintf("method not found: %s", rpc.Method))
		}
	}
}

// ─── JSON-RPC delegation ───────────────────────────────────────────────
//gollaw:keep
func (s *server) readMessage() ([]byte, error)  { return s.conn.ReadMessage() }
//gollaw:keep
func (s *server) writeMessage(data []byte) error { return s.conn.WriteMessage(data) }
//gollaw:keep
func (s *server) sendResponse(id json.RawMessage, result interface{}) {
	s.conn.SendResponse(id, result)
}
//gollaw:keep
func (s *server) sendError(id json.RawMessage, code int, message string) {
	s.conn.SendError(id, code, message)
}

func (s *server) sendNotification(method string, params interface{}) {
	notif := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  method,
		"params":  params,
	}
	data, err := json.Marshal(notif)
	if err != nil {
		s.logger.Printf("marshal notification error: %v", err)
		return
	}
	s.writeMessage(data)
}

// ─── Handlers ──────────────────────────────────────────────────────────

func (s *server) handleInitialize(id json.RawMessage, params json.RawMessage) {
	var p initializeParams
	if len(params) > 0 {
		json.Unmarshal(params, &p)
	}
	// Determine root path from RootURI or RootPath.
	if p.RootURI != "" {
		s.rootPath = uriToPath(p.RootURI)
	} else if p.RootPath != "" {
		s.rootPath = p.RootPath
	}

	result := initializeResult{
		Capabilities: serverCapabilities{
			TextDocumentSync: 1, // Full document sync
			HoverProvider:    true,
		},
		ServerInfo: serverInfo{
			Name:    "gollaw",
			Version: "0.1.0",
		},
	}
	s.sendResponse(id, result)
}

func (s *server) handleDidOpen(params json.RawMessage) {
	var p didOpenParams
	if err := json.Unmarshal(params, &p); err != nil {
		s.logger.Printf("didOpen unmarshal: %v", err)
		return
	}
	s.docs[p.TextDocument.URI] = &document{
		text:    p.TextDocument.Text,
		version: p.TextDocument.Version,
	}
	s.scheduleAnalysis(p.TextDocument.URI)
}

func (s *server) handleDidChange(params json.RawMessage) {
	var p didChangeParams
	if err := json.Unmarshal(params, &p); err != nil {
		s.logger.Printf("didChange unmarshal: %v", err)
		return
	}
	doc, ok := s.docs[p.TextDocument.URI]
	if !ok {
		// Document not open; create it.
		doc = &document{}
		s.docs[p.TextDocument.URI] = doc
	}
	doc.version = p.TextDocument.Version
	// Full sync: last change is the full document text.
	if len(p.ContentChanges) > 0 {
		doc.text = p.ContentChanges[len(p.ContentChanges)-1].Text
	}
	s.scheduleAnalysis(p.TextDocument.URI)
}

func (s *server) handleDidClose(params json.RawMessage) {
	var p struct {
		TextDocument textDocumentIdentifier `json:"textDocument"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return
	}
	// Clear diagnostics for the closed document.
	s.sendNotification("textDocument/publishDiagnostics", publishDiagnosticsParams{
		URI:         p.TextDocument.URI,
		Diagnostics: []diagnostic{},
	})
	delete(s.docs, p.TextDocument.URI)
}

func (s *server) handleHover(id json.RawMessage, params json.RawMessage) {
	var p hoverParams
	if err := json.Unmarshal(params, &p); err != nil {
		s.sendError(id, -32602, "invalid hover params")
		return
	}

	filePath := uriToPath(p.TextDocument.URI)
	// LSP positions are 0-indexed; Go findings are 1-indexed.
	targetLine := p.Position.Line + 1

	// Run analysis to get findings (in a real server this would be cached).
	findings := s.runAnalysis()
	var hoverText strings.Builder
	for _, f := range findings {
		if f.File != filePath {
			continue
		}
		endLine := f.EndLine
		if endLine == 0 {
			endLine = f.Line
		}
		if f.Line <= targetLine && targetLine <= endLine {
			fmt.Fprintf(&hoverText, "**%s** (%s)\n\n", f.Message, f.RuleID)
			fmt.Fprintf(&hoverText, "Severity: %s\n", f.Severity)
			fmt.Fprintf(&hoverText, "Category: %s\n", f.Category)
			fmt.Fprintf(&hoverText, "Analyzer: %s\n", f.Analyzer)
			if f.Detail != "" {
				fmt.Fprintf(&hoverText, "\n%s\n", f.Detail)
			}
			if f.Suggestion != "" {
				fmt.Fprintf(&hoverText, "\n💡 %s\n", f.Suggestion)
			}
		}
	}

	if hoverText.Len() == 0 {
		s.sendResponse(id, nil)
		return
	}
	s.sendResponse(id, hoverResult{
		Contents: markupContent{
			Kind:  "markdown",
			Value: hoverText.String(),
		},
	})
}

// ─── Analysis ─────────────────────────────────────────────────────────

func (s *server) scheduleAnalysis(uri string) {
	s.timerMu.Lock()
	defer s.timerMu.Unlock()
	if s.timer != nil {
		s.timer.Stop()
	}
	s.timer = time.AfterFunc(500*time.Millisecond, func() {
		findings := s.runAnalysis()
		s.publishDiagnostics(findings)
	})
}

// runAnalysis loads the codebase and runs all analyzers.
// Returns all findings (not filtered by file).
func (s *server) runAnalysis() []analyzer.Finding {
	dir := s.rootPath
	result, err := loader.Load(loader.LoadConfig{
		Patterns: []string{"./..."},
		Dir:      dir,
	})
	if err != nil {
		s.logger.Printf("load error: %v", err)
		return nil
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
			s.logger.Printf("analyzer %s error: %v", a.Name(), err)
			continue
		}
		allFindings = append(allFindings, findings...)
	}
	return allFindings
}

// publishDiagnostics groups findings by file and sends a publishDiagnostics
// notification for each file.
func (s *server) publishDiagnostics(findings []analyzer.Finding) {
	// Group by file.
	byFile := make(map[string][]analyzer.Finding)
	for _, f := range findings {
		byFile[f.File] = append(byFile[f.File], f)
	}

	for filePath, fileFindings := range byFile {
		diags := make([]diagnostic, 0, len(fileFindings))
		for _, f := range fileFindings {
			diags = append(diags, findingToDiagnostic(f))
		}
		uri := pathToURI(filePath)
		s.sendNotification("textDocument/publishDiagnostics", publishDiagnosticsParams{
			URI:         uri,
			Diagnostics: diags,
		})
	}

	// Clear diagnostics for open documents that have no findings.
	for uri := range s.docs {
		filePath := uriToPath(uri)
		if _, ok := byFile[filePath]; !ok {
			s.sendNotification("textDocument/publishDiagnostics", publishDiagnosticsParams{
				URI:         uri,
				Diagnostics: []diagnostic{},
			})
		}
	}
}

// findingToDiagnostic converts an analyzer.Finding to an LSP Diagnostic.
func findingToDiagnostic(f analyzer.Finding) diagnostic {
	// Go positions are 1-indexed; LSP positions are 0-indexed.
	line := f.Line - 1
	if line < 0 {
		line = 0
	}
	endLine := f.EndLine - 1
	if endLine < 0 {
		endLine = line
	}
	col := f.Column - 1
	if col < 0 {
		col = 0
	}

	return diagnostic{
		Range: textRange{
			Start: position{Line: line, Character: col},
			End:   position{Line: endLine, Character: col},
		},
		Severity: severityToLSP(f.Severity),
		Source:   "gollaw",
		Message:  f.Message,
		Code:     f.RuleID,
	}
}

// severityToLSP maps Gollaw severity to LSP diagnostic severity.
// LSP: 1=Error, 2=Warning, 3=Information, 4=Hint.
func severityToLSP(sev analyzer.Severity) int {
	switch sev {
	case analyzer.SeverityCritical:
		return 1
	case analyzer.SeverityWarning:
		return 2
	case analyzer.SeverityInfo:
		return 3
	case analyzer.SeverityHint:
		return 4
	default:
		return 3
	}
}

// ─── URI helpers ──────────────────────────────────────────────────────

// uriToPath converts a file:// URI to a filesystem path.
func uriToPath(uri string) string {
	if strings.HasPrefix(uri, "file://") {
		return strings.TrimPrefix(uri, "file://")
	}
	return uri
}

// pathToURI converts a filesystem path to a file:// URI.
func pathToURI(path string) string {
	if strings.HasPrefix(path, "file://") {
		return path
	}
	return "file://" + path
}

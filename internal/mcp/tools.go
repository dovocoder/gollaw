package mcp

import "encoding/json"

// toolDefs returns the full list of MCP tool definitions.
// Extracted from handleToolsList to keep server.go focused on protocol handling.
//gollaw:keep
func toolDefs() []toolDef {
	return []toolDef{
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
				},
			},
		},
		{
			Name:        "gollaw_list_analyzers",
			Description: "List all available Gollaw analyzers.",
			InputSchema: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
		{
			Name:        "gollaw_explain",
			Description: "Explain why a symbol is flagged by an analyzer.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"symbol": map[string]interface{}{"type": "string", "description": "Symbol name to explain"},
					"dir":    map[string]interface{}{"type": "string", "description": "Project directory"},
				},
				"required": []string{"symbol"},
			},
		},
		{
			Name:        "gollaw_trace",
			Description: "Trace call chain for a symbol.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"symbol":   map[string]interface{}{"type": "string", "description": "Symbol name to trace"},
					"dir":      map[string]interface{}{"type": "string", "description": "Project directory"},
					"max_depth": map[string]interface{}{"type": "integer", "description": "Max trace depth (default 5)"},
					"direction": map[string]interface{}{"type": "string", "enum": []string{"callers", "callees"}},
				},
				"required": []string{"symbol"},
			},
		},
		{
			Name:        "gollaw_health",
			Description: "Get health score for the codebase.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"dir": map[string]interface{}{"type": "string", "description": "Project directory"},
				},
			},
		},
		{
			Name:        "gollaw_audit",
			Description: "Run PR audit: analyze changed files and return verdict.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"dir":      map[string]interface{}{"type": "string", "description": "Project directory"},
					"base_ref": map[string]interface{}{"type": "string", "description": "Base ref (default: origin/main)"},
				},
			},
		},
		{
			Name:        "gollaw_guard",
			Description: "Get architecture guard report for a file.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"file_path": map[string]interface{}{"type": "string", "description": "File to check"},
					"rules":     map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}, "description": "Architecture rules"},
				},
				"required": []string{"file_path"},
			},
		},
		{
			Name:        "gollaw_baseline_save",
			Description: "Save current findings as baseline.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"dir": map[string]interface{}{"type": "string", "description": "Project directory"},
				},
			},
		},
		{
			Name:        "gollaw_baseline_diff",
			Description: "Diff current findings against baseline.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"dir": map[string]interface{}{"type": "string", "description": "Project directory"},
				},
			},
		},
		{
			Name:        "gollaw_public_api",
			Description: "Analyze the public API surface.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"dir": map[string]interface{}{"type": "string", "description": "Project directory"},
				},
			},
		},
		{
			Name:        "gollaw_coverage",
			Description: "Analyze test coverage gaps.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"dir": map[string]interface{}{"type": "string", "description": "Project directory"},
				},
			},
		},
		{
			Name:        "gollaw_file_scores",
			Description: "Get per-file health scores.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"dir": map[string]interface{}{"type": "string", "description": "Project directory"},
				},
			},
		},
		{
			Name:        "gollaw_xref",
			Description: "Cross-reference findings.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"dir": map[string]interface{}{"type": "string", "description": "Project directory"},
				},
			},
		},
		{
			Name:        "gollaw_dupes",
			Description: "Find duplicate code only.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"dir": map[string]interface{}{"type": "string", "description": "Project directory"},
				},
			},
		},
		{
			Name:        "gollaw_security",
			Description: "Find security issues only.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"dir": map[string]interface{}{"type": "string", "description": "Project directory"},
				},
			},
		},
		{
			Name:        "gollaw_impact",
			Description: "Get impact report.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"dir": map[string]interface{}{"type": "string", "description": "Project directory"},
				},
			},
		},
		{
			Name:        "gollaw_inspect",
			Description: "Inspect a file or symbol.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"target": map[string]interface{}{"type": "string", "description": "File path or symbol name"},
					"dir":    map[string]interface{}{"type": "string", "description": "Project directory"},
				},
				"required": []string{"target"},
			},
		},
		{
			Name:        "gollaw_list_boundaries",
			Description: "List architecture boundaries.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"dir": map[string]interface{}{"type": "string", "description": "Project directory"},
				},
			},
		},
		{
			Name:        "gollaw_project_info",
			Description: "Get project info.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"dir": map[string]interface{}{"type": "string", "description": "Project directory"},
				},
			},
		},
		{
			Name:        "gollaw_check_changed",
			Description: "Analyze only changed files.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"dir":      map[string]interface{}{"type": "string", "description": "Project directory"},
					"base_ref": map[string]interface{}{"type": "string", "description": "Base ref"},
				},
			},
		},
		{
			Name:        "gollaw_suppress",
			Description: "Find stale suppressions.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"dir": map[string]interface{}{"type": "string", "description": "Project directory"},
				},
			},
		},
		{
			Name:        "gollaw_owners",
			Description: "Group findings by CODEOWNERS.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"dir": map[string]interface{}{"type": "string", "description": "Project directory"},
				},
			},
		},
		{
			Name:        "gollaw_fix_preview",
			Description: "Preview auto-fixes.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"dir":      map[string]interface{}{"type": "string", "description": "Project directory"},
					"analyzer": map[string]interface{}{"type": "string", "description": "Filter by analyzer"},
				},
			},
		},
	}
}

func (s *server) handleToolsList(id json.RawMessage) {
	s.sendResponse(id, toolsListResult{Tools: toolDefs()})
}

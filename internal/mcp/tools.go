package mcp

import "encoding/json"

// dirProperty returns the standard "dir" property schema used by most tools.
func dirProperty() map[string]interface{} {
	return map[string]interface{}{
		"type":        "string",
		"description": "Project directory",
	}
}

// dirOnlyTool creates a toolDef with just a "dir" property.
func dirOnlyTool(name, desc string) toolDef {
	return toolDef{
		Name:        name,
		Description: desc,
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{"dir": dirProperty()},
		},
	}
}

// dirBaseRefTool creates a toolDef with "dir" and "base_ref" properties.
func dirBaseRefTool(name, desc, baseRefDesc string) toolDef {
	return toolDef{
		Name:        name,
		Description: desc,
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"dir":      dirProperty(),
				"base_ref": map[string]interface{}{"type": "string", "description": baseRefDesc},
			},
		},
	}
}

// coreToolDefs returns tool definitions for core analysis tools.
func coreToolDefs() []toolDef {
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
					"dir":    dirProperty(),
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
					"dir":      dirProperty(),
					"max_depth": map[string]interface{}{"type": "integer", "description": "Max trace depth (default 5)"},
					"direction": map[string]interface{}{"type": "string", "enum": []string{"callers", "callees"}},
				},
				"required": []string{"symbol"},
			},
		},
	}
}

// qualityToolDefs returns tool definitions for code quality and audit tools.
func qualityToolDefs() []toolDef {
	return []toolDef{
		dirOnlyTool("gollaw_health", "Get health score for the codebase."),
		dirBaseRefTool("gollaw_audit", "Run PR audit: analyze changed files and return verdict.", "Base ref (default: origin/main)"),
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
		dirOnlyTool("gollaw_baseline_save", "Save current findings as baseline."),
		dirOnlyTool("gollaw_baseline_diff", "Diff current findings against baseline."),
		dirOnlyTool("gollaw_public_api", "Analyze the public API surface."),
		dirOnlyTool("gollaw_coverage", "Analyze test coverage gaps."),
	}
}

// inspectionToolDefs returns tool definitions for inspection and reporting tools.
func inspectionToolDefs() []toolDef {
	return []toolDef{
		dirOnlyTool("gollaw_file_scores", "Get per-file health scores."),
		dirOnlyTool("gollaw_xref", "Cross-reference findings."),
		dirOnlyTool("gollaw_dupes", "Find duplicate code only."),
		dirOnlyTool("gollaw_security", "Find security issues only."),
		dirOnlyTool("gollaw_impact", "Get impact report."),
		{
			Name:        "gollaw_inspect",
			Description: "Inspect a file or symbol.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"target": map[string]interface{}{"type": "string", "description": "File path or symbol name"},
					"dir":    dirProperty(),
				},
				"required": []string{"target"},
			},
		},
		dirOnlyTool("gollaw_list_boundaries", "List architecture boundaries."),
		dirOnlyTool("gollaw_project_info", "Get project info."),
	}
}

// maintenanceToolDefs returns tool definitions for maintenance utilities.
func maintenanceToolDefs() []toolDef {
	return []toolDef{
		dirBaseRefTool("gollaw_check_changed", "Analyze only changed files.", "Base ref"),
		dirOnlyTool("gollaw_suppress", "Find stale suppressions."),
		dirOnlyTool("gollaw_owners", "Group findings by CODEOWNERS."),
		{
			Name:        "gollaw_fix_preview",
			Description: "Preview auto-fixes.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"dir":      dirProperty(),
					"analyzer": map[string]interface{}{"type": "string", "description": "Filter by analyzer"},
				},
			},
		},
	}
}

// toolDefs returns the full list of MCP tool definitions.
// Extracted from handleToolsList to keep server.go focused on protocol handling.
func toolDefs() []toolDef {
	all := coreToolDefs()
	all = append(all, qualityToolDefs()...)
	all = append(all, inspectionToolDefs()...)
	all = append(all, maintenanceToolDefs()...)
	return all
}

//gollaw:ignore thin-wrappers
func (s *server) handleToolsList(id json.RawMessage) {
	s.sendResponse(id, toolsListResult{Tools: toolDefs()})
}

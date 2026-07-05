# Integration

## Editor Integration (LSP)

Gollaw includes a Language Server Protocol server for real-time editor integration.

```bash
gollaw lsp
```

### Features

- **Live diagnostics** — findings appear as you type
- **Code actions** — quick-fix suggestions (remove dead code, add suppression)
- **Code lens** — shows complexity per function inline
- **Hover** — markdown hover with finding details
- **Suppression** — respects `//gollaw:keep` comments

### VS Code

Add to `.vscode/settings.json`:

```json
{
  "go.lspServer": "gollaw lsp"
}
```

Or use with `gopls` alongside (Gollaw as a secondary diagnostic source):

```json
{
  "go.lspServer": "gopls",
  "go.alternateTools": {
    "gollaw": "gollaw"
  }
}
```

### Neovim

```lua
-- init.lua
require('lspconfig').gollaw.setup{
  cmd = { "gollaw", "lsp" },
  filetypes = { "go" },
  root_dir = require('lspconfig').util.root_pattern("go.mod", ".git"),
}
```

### Helix

```toml
# .config/helix/languages.toml
[language-server.gollaw]
command = "gollaw"
args = ["lsp"]
```

---

## AI Agent Integration (MCP)

Gollaw includes a Model Context Protocol server with 23 tools for AI agents.

```bash
gollaw mcp
```

### Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "gollaw": {
      "command": "gollaw",
      "args": ["mcp"]
    }
  }
}
```

### Available Tools (23)

| Tool | Description |
|------|-------------|
| `gollaw_analyze` | Run full codebase analysis |
| `gollaw_audit` | PR audit against base branch |
| `gollaw_guard` | Check architecture rules |
| `gollaw_baseline_save` | Save findings baseline |
| `gollaw_baseline_diff` | Compare to baseline |
| `gollaw_public_api` | API surface analysis |
| `gollaw_coverage` | Test coverage gaps |
| `gollaw_file_scores` | Per-file health scores |
| `gollaw_xref` | Cross-reference findings |
| `gollaw_dupes` | Find duplicate code |
| `gollaw_security` | Security findings |
| `gollaw_impact` | Impact analysis |
| `gollaw_inspect` | File/symbol inspection |
| `gollaw_list_boundaries` | List architecture boundaries |
| `gollaw_project_info` | Project overview |
| `gollaw_check_changed` | Analyze changed files |
| `gollaw_suppress` | List suppression comments |
| `gollaw_owners` | CODEOWNERS mapping |
| `gollaw_fix_preview` | Preview auto-fixes |
| `gollaw_explain` | Explain a finding |
| `gollaw_trace` | Trace call graph |
| `gollaw_health` | Health score |
| `gollaw_list_analyzers` | List available analyzers |

### Example: Using with an AI agent

An AI agent can use Gollaw to:

1. **Analyze a codebase** — `gollaw_analyze` for a full report
2. **Find dead code** — `gollaw_analyze` with `analyzers: ["deadcode"]`
3. **Check PR impact** — `gollaw_audit` with base ref
4. **Explain a finding** — `gollaw_explain` with symbol name
5. **Trace call paths** — `gollaw_trace` with symbol and direction
6. **Preview fixes** — `gollaw_fix_preview` before applying

---

## File Watcher

```bash
gollaw watch
```

Re-runs analysis automatically when files change. Useful during development for
instant feedback.

---

## GitHub Action

Gollaw's own CI is available as a reusable workflow:

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0
- uses: actions/setup-go@v5
  with:
    go-version: '1.23'
- run: go install github.com/dovocoder/gollaw@latest
- run: gollaw audit --base-ref origin/main --format markdown
```

See [CI/CD Integration](ci-cd.md) for more examples.

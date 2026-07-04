# Gollaw

> Whole-codebase intelligence for Go — like Fallow, but for Go.

Gollaw analyzes an entire Go codebase using the compiler's own semantic model
(`go/packages`, `go/types`, `go/ssa`, `go/ast`) to surface dead code, unused
exports, complexity hotspots, duplication, dependency cycles, security issues,
naming violations, architecture violations, coverage gaps, and more — all from
a single tool with JSON output designed for AI agents.

## Quick start

```bash
go install github.com/dovocoder/gollaw@latest

# Analyze current project
gollaw analyze ./...

# PR audit — only changed files, with verdict
gollaw audit --base-ref origin/main

# JSON output for AI agents
gollaw analyze ./... --format json

# Only specific analyzers
gollaw analyze ./... --analyzers deadcode,complexity,duplication

# Architecture rules
gollaw analyze ./... --rule "internal/store must not import internal/api"
```

## Commands

| Command | Description |
|---------|-------------|
| `analyze` | Run analyzers on a Go codebase |
| `audit` | PR audit: analyze changed files vs base ref, give verdict |
| `guard` | Pre-edit architecture guidance for a file |
| `explain` | Explain why a symbol is unused/dead |
| `trace` | Trace callers/callees of a symbol |
| `baseline` | Save or diff against a findings baseline |
| `health` | Get project health score |
| `file-scores` | Per-file health scores |
| `xref` | Cross-reference findings (e.g. duplicate + dead) |
| `public-api` | Analyze public API surface |
| `coverage` | Test coverage gap analysis |
| `owners` | Group findings by CODEOWNERS |
| `init` | Create .gollaw.yaml config file |
| `list` | List available analyzers |
| `lsp` | Start LSP server (editor integration) |
| `mcp` | Start MCP server (AI agent integration) |
| `watch` | Watch for file changes and re-analyze |

## Analyzers (14)

| Analyzer | What it finds |
|----------|--------------|
| `deadcode` | Unreachable functions via SSA call graph |
| `unused` | Unused exported identifiers |
| `complexity` | Cyclomatic + cognitive complexity hotspots |
| `duplication` | Duplicate code blocks (AST-based clone detection) |
| `dependencies` | Import cycles and dependency hygiene |
| `architecture` | Architecture boundary violations |
| `unused-deps` | go.mod dependencies that are never imported |
| `large-functions` | Functions exceeding a line-count threshold |
| `hotspots` | Files with high complexity density (maintenance risk areas) |
| `security` | Hardcoded secrets, TODO/FIXME comments, unsafe usage, SQL injection |
| `naming` | Go naming convention violations (snake_case, ALL_CAPS, initialisms) |
| `unused-files` | Go files not part of any loaded package |
| `thin-wrappers` | Functions that just delegate to a single call |
| `churn` | Files with high git churn (frequent changes = maintenance hotspots) |

## Output formats

- `text` (default) — human-readable
- `json` — structured, for AI agents and CI
- `sarif` — SARIF 2.1.0 for GitHub Code Scanning
- `markdown` — for PR comments (audit command)

## Config file

Create `.gollaw.yaml` in your project root (or run `gollaw init`):

```yaml
analyzers:
  enabled: []  # empty = all
  disabled: [naming]  # disable specific analyzers

thresholds:
  max-cyclomatic: 15
  max-cognitive: 20
  max-function-lines: 50
  min-dup-lines: 6

rules:
  - "internal/store must not import internal/api"
  - "internal/cli must not import internal/analyzer"

ignore:
  - "vendor/**"
  - "**/*_test.go"

severity:
  min: hint
```

## Suppressions

Inline suppression comments:

```go
//gollaw:keep
func legacyHandler() { ... }  // suppress deadcode/unused

//gollaw:ignore complexity
func complexButIntentional() { ... }  // suppress specific analyzer

//gollaw:ignore-all
// suppresses all findings in this file
```

## Baseline mode

Store a snapshot and only see new issues:

```bash
gollaw baseline save     # snapshot current findings
gollaw baseline diff     # show only new findings since baseline
gollaw analyze --baseline  # analyze + only show new issues
```

## PR audit

Analyze only changed files, with attribution:

```bash
gollaw audit --base-ref origin/main
gollaw audit --base-ref origin/main --format markdown  # for PR comments
gollaw audit --base-ref origin/main --format json      # for CI pipelines
```

Verdict: **pass** (no new critical/warning), **warn** (new warnings), **fail** (new critical).

## Editor integration (LSP)

```bash
gollaw lsp  # start LSP server over stdio
```

Add to VS Code `settings.json`:
```json
{
  "gollaw.path": "/path/to/gollaw",
  "gollaw.enable": true
}
```

## AI agent integration (MCP)

```bash
gollaw mcp  # start MCP server over stdio
```

Exposes tools: `gollaw_analyze`, `gollaw_list_analyzers`, `gollaw_explain`,
`gollaw_trace`, `gollaw_health`.

## GitHub Action

Use in your CI workflow:

```yaml
- uses: dovocoder/gollaw@v1
  with:
    base-ref: origin/main
    format: markdown
```

Or see `.github/workflows/gollaw.yml` for a complete workflow.

## Health score

Gollaw computes a 0-100 health score from a weighted blend of all analyzers,
giving a single number for tracking codebase quality over time. Per-file scores
are also available via `gollaw file-scores`.

## Cross-reference analysis

```bash
gollaw xref  # find overlapping findings from different analyzers
```

Detects patterns like:
- **duplicate-and-dead**: duplicated code that is also unreachable
- **duplicate-and-unused**: duplicated code that is also unused
- **complex-and-large**: functions that are both complex and long
- **security-and-dead**: security issues in dead code

## Public API analysis

```bash
gollaw public-api
```

Classifies exports as:
- **Confirmed public API** — used by external importers
- **Accidental exports** — only used within own package (should be unexported)
- **Unused exports** — not used anywhere

## Coverage analysis

```bash
gollaw coverage
```

Finds functions with no test coverage — functions that have no corresponding
`TestXxx` function and are not called from any test.

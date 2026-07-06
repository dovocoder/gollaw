# Gollaw

> Whole-codebase intelligence for Go — find dead code, complexity hotspots, duplication, architecture violations, and more.

[![Go Reference](https://pkg.go.dev/badge/github.com/dovocoder/gollaw.svg)](https://pkg.go.dev/github.com/dovocoder/gollaw)
[![Go Report Card](https://goreportcard.com/badge/github.com/dovocoder/gollaw)](https://goreportcard.com/report/github.com/dovocoder/gollaw)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Gollaw analyzes an entire Go codebase using the compiler's own semantic model
(`go/packages`, `go/types`, `go/ssa`, `go/ast`) to find dead code, unused exports,
complexity hotspots, duplication, architecture violations, security issues, and more.

It is the Go equivalent of [Fallow](https://github.com/nilsso/fallow) (Rust).

---

## Quick Start

```bash
# Install
go install github.com/dovocoder/gollaw@latest

# Analyze your codebase
cd your-project
gollaw analyze .

# Or download a prebuilt binary
# See https://github.com/dovocoder/gollaw/releases
```

## Table of Contents

- [Installation](#installation)
- [Commands](#commands)
- [Analyzers](#analyzers-21)
- [Output Formats](#output-formats)
- [Configuration](#configuration)
- [Suppression Comments](#suppression-comments)
- [CI/CD Integration](#cicd-integration)
- [Editor Integration](#editor-integration-lsp)
- [AI Agent Integration](#ai-agent-integration-mcp)
- [Health Score](#health-score)
- [Self-Analysis](#self-analysis)

---

## Installation

### From source

```bash
go install github.com/dovocoder/gollaw@latest
```

### Prebuilt binaries

Download from [GitHub Releases](https://github.com/dovocoder/gollaw/releases):

```bash
# Linux/macOS
tar xzf gollaw_0.3.0_linux_amd64.tar.gz
sudo mv gollaw /usr/local/bin/
gollaw version
```

| OS | Arch | Download |
|---|---|---|
| Linux | amd64 | `gollaw_*_linux_amd64.tar.gz` |
| Linux | arm64 | `gollaw_*_linux_arm64.tar.gz` |
| macOS (Intel) | amd64 | `gollaw_*_darwin_amd64.tar.gz` |
| macOS (Apple Silicon) | arm64 | `gollaw_*_darwin_arm64.tar.gz` |
| Windows | amd64 | `gollaw_*_windows_amd64.zip` |
| Windows | arm64 | `gollaw_*_windows_arm64.zip` |
| FreeBSD | amd64 | `gollaw_*_freebsd_amd64.tar.gz` |

### Build from source

```bash
git clone https://github.com/dovocoder/gollaw.git
cd gollaw
go build -o gollaw .
```

---

## Commands

### `analyze` — Run analysis

```bash
# Analyze the current directory
gollaw analyze .

# Analyze specific packages
gollaw analyze ./internal/...

# Select specific analyzers
gollaw analyze . -a deadcode,complexity

# Filter by severity
gollaw analyze . --min-severity warning

# Disable suppression comments
gollaw analyze . --no-suppress

# Compare against baseline
gollaw analyze . --baseline
```

**Flags:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--format` | `-f` | `text` | Output format: `text`, `json`, `sarif`, `markdown` |
| `--analyzers` | `-a` | all | Comma-separated analyzer names |
| `--dir` | | `.` | Working directory |
| `--rule` | | | Architecture rule: `"pkg must not import other"` |
| `--min-severity` | | `warning` | Minimum severity: `critical`, `warning`, `info`, `hint` |
| `--max-cyclomatic` | | `15` | Max cyclomatic complexity |
| `--max-cognitive` | | `20` | Max cognitive complexity |
| `--min-dup-lines` | | `5` | Min lines for duplication detection |
| `--no-config` | | | Ignore `.gollaw.yaml` |
| `--no-suppress` | | | Ignore `//gollaw:keep` comments |
| `--baseline` | | | Show only new findings vs baseline |

### `health` — Health score

```bash
gollaw health
```
```
Health Score: 94/100 (grade: A)
  by category:
    code-smell: -6
```

### `file-scores` — Per-file health

```bash
gollaw file-scores
```

### `audit` — PR audit

```bash
gollaw audit --base-ref origin/main --format markdown
```

Compares findings against a base branch. Returns exit code 1 if verdict is "fail".

### `guard` — Architecture guard

```bash
# List configured rules
gollaw guard list

# Check a file against rules
gollaw guard check internal/handler/handler.go
```

### `explain` — Symbol explanation

```bash
gollaw explain MyFunction
```

Explains why a symbol is flagged as dead/unused.

### `trace` — Call graph tracing

```bash
# Trace callers of a function
gollaw trace MyFunction

# Trace callees
gollaw trace MyFunction --direction callees

# Set max depth
gollaw trace MyFunction --depth 5
```

### `baseline` — Baseline management

```bash
# Save current findings as baseline
gollaw baseline save

# Show new findings since baseline
gollaw baseline diff

# Show saved baseline
gollaw baseline show
```

### `trends` — Health trends

```bash
# Save a health snapshot
gollaw trends --save

# Show trend history
gollaw trends
```

### `vital-signs` — Project overview

```bash
gollaw vital-signs
```

Shows codebase metrics: files, packages, functions, findings by severity, health score.

### `targets` — Refactoring targets

```bash
gollaw targets
```

Ranks files by finding count and severity to prioritize refactoring.

### `coverage` — Test coverage gaps

```bash
gollaw coverage
```

Identifies functions with no test coverage.

### `public-api` — API surface analysis

```bash
gollaw public-api
```

Lists all exported identifiers and their usage status.

### `xref` — Cross-reference findings

```bash
gollaw xref
```

Groups findings that reference the same symbol across analyzers.

### `inspect` — File/symbol inspection

```bash
# Inspect a file
gollaw inspect internal/handler/handler.go

# Inspect a symbol
gollaw inspect MyFunction
```

### `impact` — Impact analysis

```bash
gollaw impact main.go
```

Shows blast radius of changes to a file.

### `walkthrough` — Guided walkthrough

```bash
gollaw walkthrough
```

Generates a step-by-step guide to fix findings, sorted by priority.

### `timings` — Analyzer performance

```bash
gollaw timings
```

Shows how long each analyzer takes.

### `init` — Create config

```bash
gollaw init .
```

Creates a `.gollaw.yaml` config file with defaults.

### `fix` — Auto-fix findings

```bash
# Preview fixes
gollaw fix --dry-run

# Apply fixes
gollaw fix --analyzer deadcode
```

### `migrate` — Migrate from other tools

```bash
# Check what can be migrated
gollaw migrate --check

# Migrate staticcheck config
gollaw migrate staticcheck

# Migrate golangci-lint config
gollaw migrate golangci-lint
```

### `rule-pack` — Pre-built rule packs

```bash
gollaw rule-pack
```

Lists available pre-built architecture rule packs (e.g., clean-architecture, hexagonal).

### `list` — List analyzers

```bash
gollaw list
```

### `version` — Version info

```bash
gollaw version
```

### `lsp` — LSP server

```bash
gollaw lsp
```

Starts the Language Server Protocol server for editor integration.

### `mcp` — MCP server

```bash
gollaw mcp
```

Starts the Model Context Protocol server for AI agent integration.

### `watch` — File watcher

```bash
gollaw watch
```

Re-runs analysis on file changes.

---

## Analyzers (22)

| Analyzer | ID | Description |
|----------|-----|-------------|
| `deadcode` | GLW-DC001 | Unreachable functions via SSA instruction analysis |
| `unused` | GLW-U001 | Exported identifiers never used outside their package |
| `complexity` | GLW-CC001 | Cyclomatic and cognitive complexity hotspots |
| `duplication` | GLW-DP001 | Duplicate code blocks via AST structural hashing |
| `dependencies` | GLW-DE001 | Import graph cycles and dependency hygiene |
| `architecture` | GLW-AR001 | Architecture boundary violations |
| `unused-deps` | GLW-UD001 | go.mod dependencies that are never imported |
| `large-functions` | GLW-LF001 | Functions exceeding 50 lines |
| `hotspots` | GLW-HS001 | Files with high complexity density |
| `security` | GLW-SC001 | Hardcoded secrets, TODO/FIXME, unsafe usage, SQL injection |
| `naming` | GLW-NM001 | Go naming convention violations |
| `unused-files` | GLW-UF001 | Orphaned Go files not part of any package |
| `thin-wrappers` | GLW-TW001 | Functions that only delegate to another function |
| `self-recursion` | GLW-SR001 | Functions that immediately recurse into themselves |
| `churn` | GLW-CH001 | Files with high git commit churn |
| `boundary-coverage` | GLW-BC001 | Exported functions without boundary tests |
| `feature-flags` | GLW-FF001 | Hardcoded feature flag values |
| `unused-members` | GLW-UM001 | Struct fields that are never accessed |
| `re-export-cycles` | GLW-RC001 | Re-export chains that form cycles |
| `unused-overrides` | GLW-UO001 | Interface method overrides that are never called |
| `dead-flags` | GLW-DF001 | Feature flags that are always true/false |
| `api-surface` | GLW-AS001 | Exported symbols that should be unexported |

---

## Output Formats

### Text (default)

```
Gollaw v0.3.0 — 2026-07-06T12:00:00Z
Patterns: ./...

▸ /path/to/file.go
  🔴 file.go:42 [security] hardcoded secret in variable assignment
    severity: critical
    → Move secrets to environment variables or a secret manager.
```

### JSON

```bash
gollaw analyze . --format json
```

```json
{
  "tool": "gollaw",
  "version": "0.3.0",
  "timestamp": "2026-07-05T12:00:00Z",
  "patterns": ["./..."],
  "stats": { "packages": 32, "files": 74, "functions": 853 },
  "findings": [...],
  "healthScore": { "score": 94, "grade": "A" }
}
```

### SARIF (for CI/CD)

```bash
gollaw analyze . --format sarif
```

Standard SARIF 2.1.0 format compatible with GitHub Code Scanning.

### Markdown (for PRs)

```bash
gollaw analyze . --format markdown
```

---

## Configuration

Create a `.gollaw.yaml` in your project root:

```bash
gollaw init .
```

```yaml
# Gollaw configuration
analyzers:
  enabled: []  # empty = all analyzers
  disabled: []  # e.g. ["churn", "feature-flags"]

# Architecture rules
rules:
  - "internal/handler must not import internal/storage"
  - "internal/cli must not import internal/mcp"

# Severity overrides
severity:
  GLW-CC001: warning  # complexity → warning
  GLW-LF001: info     # large-functions → info

# Thresholds
thresholds:
  max-cyclomatic: 15
  max-cognitive: 20
  min-dup-lines: 5
  max-function-lines: 50

# Suppressions
suppress:
  - file: "internal/legacy/"
    analyzer: "*"
```

---

## Suppression Comments

### Suppress all analyzers on a declaration

```go
//gollaw:keep
func legacyHandler(w http.ResponseWriter, r *http.Request) {
    // ...
}
```

### Suppress a specific analyzer

```go
//gollaw:ignore api-surface
func PublicAPI() {
    // This is intentionally exported for external use
}
```

### File-level suppression

```go
//gollaw:ignore-all
package legacy
```

---

## CI/CD Integration

### GitHub Actions

```yaml
name: gollaw
on:
  pull_request:
    branches: [main, master]

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: actions/setup-go@v5
        with:
          go-version: '1.25'

      - name: Install Gollaw
        run: go install github.com/dovocoder/gollaw@latest

      - name: Run Gollaw audit
        run: gollaw audit --base-ref origin/main --format markdown
```

### Pre-commit hook

```yaml
# .pre-commit-config.yaml
- repo: local
  hooks:
    - id: gollaw
      name: gollaw
      entry: gollaw analyze .
      language: system
      pass_filenames: false
```

### Exit codes

- `0` — No critical findings
- `1` — Critical findings present (or audit verdict: fail)

---

## Editor Integration (LSP)

```bash
gollaw lsp
```

Features:
- Live diagnostics on file open/change
- Code actions (quick-fix: remove dead code, add suppression)
- Code lens (complexity per function)
- Markdown hover with finding details
- Suppression support (`//gollaw:keep`)

### VS Code

Add to `.vscode/settings.json`:

```json
{
  "gopls": {
    "formatting.gofmt": true
  },
  "go.lspServer": "gollaw lsp"
}
```

### Neovim

```lua
require('lspconfig').gollaw.setup{}
```

---

## AI Agent Integration (MCP)

```bash
gollaw mcp
```

Starts an MCP (Model Context Protocol) server with 23 tools:

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
| `gollaw_security` | Security findings only |
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

### Usage with Claude Desktop

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

---

## Health Score

The health score is calculated as:

```
score = 100 - sqrt(penalty_per_100_functions) * 10
```

Where penalty per finding:
- Critical: 8
- Warning: 4
- Info: 2
- Hint: 1

| Grade | Score | Description |
|-------|-------|-------------|
| A | 90-100 | Excellent — minimal technical debt |
| B | 80-89 | Good — minor issues |
| C | 70-79 | Fair — some refactoring needed |
| D | 60-69 | Poor — significant debt |
| F | 0-59 | Critical — immediate action needed |

---

## Self-Analysis

Gollaw analyzes its own codebase:

```
Health Score: 94/100 (grade: A)

Findings: 3 (all churn — informational)
  deadcode.go:  high churn (10 changes in 6 months)
  cli.go:       high churn (11 changes in 6 months)
  server.go:    high churn (10 changes in 6 months)

0 //gollaw:keep suppressions
8 //gollaw:ignore (targeted: api-surface, thin-wrappers, deadcode)
```

---

## License

MIT

# Gollaw

> Whole-codebase intelligence for Go — like Fallow, but for Go.

Gollaw analyzes an entire Go codebase using the compiler's own semantic model
(`go/packages`, `go/types`, `go/ssa`, `go/ast`) to surface dead code, unused
exports, complexity hotspots, duplication, dependency cycles, and architecture
violations — all from a single tool with JSON output designed for AI agents.

## Quick start

```bash
go install github.com/dovocoder/gollaw@latest

# Analyze current project
gollaw analyze ./...

# JSON output for AI agents
gollaw analyze ./... --format json

# Only specific analyzers
gollaw analyze ./... --analyzers deadcode,complexity,duplication

# Architecture rules
gollaw analyze ./... --rule "internal/store must not import internal/api"
```

## Analyzers

| Analyzer | What it finds |
|----------|--------------|
| `deadcode` | Unreachable functions via SSA call graph |
| `unused` | Unused exported identifiers |
| `complexity` | Cyclomatic + cognitive complexity hotspots |
| `duplication` | Duplicate code blocks (AST-based clone detection) |
| `dependencies` | Import cycles and dependency hygiene |
| `architecture` | Architecture boundary violations |

## Output formats

- `text` (default) — human-readable
- `json` — structured, for AI agents and CI
- `sarif` — SARIF 2.1.0 for GitHub Code Scanning

## Health score

Gollaw computes a 0-100 health score from a weighted blend of all analyzers,
giving a single number for tracking codebase quality over time.

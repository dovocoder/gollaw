# Getting Started

## Prerequisites

- Go 1.25 or later
- A Go module (`go.mod` present)

## Installation

### Option 1: `go install`

```bash
go install github.com/dovocoder/gollaw@latest
```

This places the `gollaw` binary in `$GOPATH/bin` (usually `~/go/bin`).

### Option 2: Download binary

See [Releases](https://github.com/dovocoder/gollaw/releases) for prebuilt binaries:

```bash
# Linux amd64
curl -L https://github.com/dovocoder/gollaw/releases/latest/download/gollaw-v0.2.0-linux-amd64.tar.gz | tar xz
sudo mv gollaw /usr/local/bin/

# macOS Apple Silicon
curl -L https://github.com/dovocoder/gollaw/releases/latest/download/gollaw-v0.2.0-darwin-arm64.tar.gz | tar xz
sudo mv gollaw /usr/local/bin/
```

### Option 3: Build from source

```bash
git clone https://github.com/dovocoder/gollaw.git
cd gollaw
go build -o gollaw .
```

## First Analysis

```bash
cd your-go-project
gollaw analyze .
```

Output:
```
Gollaw v0.2.0 — 2026-07-05T12:00:00Z
Patterns: ./...
Analyzers: deadcode, unused, complexity, duplication, dependencies, ...

▸ internal/handler/handler.go
  🟡 handler.go:42 [complexity] processRequest has cyclomatic complexity 18 (max 15)
    → Consider extracting branches into helper functions.

Summary: 5 findings (0 critical, 1 warning, 4 info)
Health Score: 82/100 (grade: B)
```

## Key Concepts

### Findings

Each finding has:
- **Analyzer** — which analyzer detected it (e.g. `deadcode`, `complexity`)
- **Severity** — `critical`, `warning`, `info`, or `hint`
- **File:Line** — location in source
- **Message** — human-readable description
- **Suggestion** — recommended fix

### Health Score

A single number (0-100) summarizing codebase health:

```
score = 100 - sqrt(total_penalty * 100 / num_functions) * 10
```

Penalties: critical=8, warning=4, info=2, hint=1

### Suppression

Control which findings are reported using comments:

```go
//gollaw:keep                          // suppress ALL analyzers
//gollaw:ignore complexity             // suppress specific analyzer
//gollaw:ignore-all                    // suppress everything in this file
```

## Next Steps

- [CLI Reference](cli-reference.md) — all commands and flags
- [Analyzers](analyzers.md) — detailed analyzer documentation
- [Configuration](configuration.md) — `.gollaw.yaml` options
- [CI/CD Integration](ci-cd.md) — GitHub Actions, pre-commit hooks

# Gollaw

> Whole-codebase intelligence for Go — like Fallow, but for Go.

Gollaw analyzes an entire Go codebase using the compiler's own semantic model
(`go/packages`, `go/types`, `go/ssa`, `go/ast`) to find dead code, unused exports,
complexity hotspots, duplication, architecture violations, security issues, and more.

## Quick Start

```bash
go install github.com/dovocoder/gollaw@latest
gollaw analyze ./...
```

## Analyzers (21)

| Analyzer | Description |
|----------|-------------|
| `deadcode` | Unreachable functions via SSA call graph |
| `unused` | Exported identifiers never used outside their package |
| `complexity` | Cyclomatic and cognitive complexity hotspots |
| `duplication` | Duplicate code blocks via AST structural hashing |
| `dependencies` | Import graph cycles and dependency hygiene |
| `architecture` | Architecture boundary violations |
| `unused-deps` | go.mod dependencies that are never imported |
| `large-functions` | Functions exceeding a line-count threshold |
| `hotspots` | Files with high complexity density |
| `security` | Hardcoded secrets, TODO/FIXME, unsafe usage, SQL injection |
| `naming` | Go naming convention violations |
| `unused-files` | Go files not part of any loaded package |
| `thin-wrappers` | Functions that just delegate to a single call |
| `churn` | Files with high git churn |
| `boundary-coverage` | Packages not covered by any architecture rule |
| `feature-flags` | Build tags and feature gates that may guard dead code |
| `unused-members` | Unused struct fields and interface methods with no implementations |
| `re-export-cycles` | Re-export cycles between packages |
| `unused-overrides` | Unused replace directives in go.mod |
| `dead-flags` | Unused constants and flag registrations |
| `api-surface` | Intentional public API vs accidental exports |

## Commands

### Analysis
```bash
gollaw analyze ./...                          # Full analysis
gollaw analyze ./... --format json            # JSON output
gollaw analyze ./... --format sarif           # SARIF for CI
gollaw analyze ./... --format codeclimate     # CodeClimate/GitLab format
gollaw analyze ./... --format compact         # One-line per finding
gollaw analyze ./... --format grouped         # Grouped by file
gollaw analyze ./... --format markdown        # Full markdown report
gollaw analyze ./... --format pr-decision     # PR pass/fail with gates
gollaw analyze ./... --format pr-summary      # PR comment markdown
gollaw analyze ./... --format impact          # Impact report
gollaw analyze ./... --format next-steps      # Actionable recommendations
gollaw analyze ./... --analyzers deadcode     # Run specific analyzers
gollaw analyze ./... --rule "pkgA must not import pkgB"  # Architecture rules
gollaw list                                   # List all analyzers
```

### Workflow
```bash
gollaw audit --base-ref origin/main           # PR audit mode
gollaw guard <file.go> --rule "..."           # Pre-edit guidance
gollaw explain <symbol>                       # Why is this unused/dead?
gollaw trace <symbol> --direction callers     # Call chain tracing
gollaw fix --dry-run                          # Preview auto-fixes
gollaw fix --analyzer deadcode                # Apply fixes
gollaw inspect <file|symbol>                  # Interactive inspection
gollaw regression --tolerance 5               # Baseline comparison
gollaw walkthrough                            # Guided codebase tour
```

### Health & Metrics
```bash
gollaw vital-signs                            # Project-wide metrics
gollaw file-scores                            # Per-file health scores
gollaw targets                                # Refactoring targets
gollaw trends --save                          # Save snapshot + view trends
gollaw timings                                # Analyzer execution times
gollaw impact --base-ref origin/main          # Impact analysis
gollaw health                                 # Health score summary
```

### Cross-Reference & API
```bash
gollaw xref                                   # Cross-reference findings
gollaw public-api                             # Public API surface analysis
gollaw coverage                               # Test coverage gaps
gollaw owners                                 # Group findings by CODEOWNERS
```

### Baseline & Suppressions
```bash
gollaw baseline save                          # Save baseline snapshot
gollaw baseline diff                          # Show only new findings
# Inline: //gollaw:keep or //gollaw:ignore analyzer-name
```

### Configuration
```bash
gollaw init                                   # Create .gollaw.yaml
gollaw rule-pack list                         # List rule packs
gollaw rule-pack apply clean-architecture     # Apply a rule pack
gollaw rule-pack show hexagonal               # Show pack details
gollaw migrate --from golangci                # Migrate from golangci-lint
```

### Integrations
```bash
gollaw lsp                                    # Start LSP server (stdio)
gollaw mcp                                    # Start MCP server (stdio)
gollaw watch                                  # Continuous analysis on file changes
```

## Configuration (`.gollaw.yaml`)

```yaml
analyzers:
  enabled: [deadcode, unused, complexity]
  disabled: []
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
  - "**/testdata/**"
severity:
  min: hint
rule_packs:
  - name: clean-architecture
    enabled: true
plugins:
  - name: custom-check
    path: ./bin/custom-check
    enabled: true
```

## Rule Packs

Built-in architecture rule packs:
- **clean-architecture** — domain/usecase/infrastructure boundaries
- **hexagonal** — ports/adapters isolation
- **microservice** — API/store/repo separation
- **library** — no internal cycles
- **monolith** — standard layered architecture

## MCP Tools (23)

The MCP server exposes Gollaw as tools for AI agents:
`gollaw_analyze`, `gollaw_audit`, `gollaw_guard`, `gollaw_baseline_save`,
`gollaw_baseline_diff`, `gollaw_public_api`, `gollaw_coverage`,
`gollaw_file_scores`, `gollaw_xref`, `gollaw_dupes`, `gollaw_security`,
`gollaw_impact`, `gollaw_inspect`, `gollaw_list_boundaries`,
`gollaw_project_info`, `gollaw_check_changed`, `gollaw_suppress`,
`gollaw_owners`, `gollaw_fix_preview`, `gollaw_explain`, `gollaw_trace`,
`gollaw_health`, `gollaw_list_analyzers`.

## LSP Server

Editor integration with:
- Live diagnostics on file open/change
- Code actions (quick-fix: remove dead code, add suppression)
- Code lens (complexity per function)
- Markdown hover with finding details
- Suppression support (`//gollaw:keep`)

## GitHub Action

```yaml
- uses: actions/checkout@v4
  with: { fetch-depth: 0 }
- uses: actions/setup-go@v5
  with: { go-version: '1.23' }
- run: go install github.com/dovocoder/gollaw@latest
- run: gollaw audit --base-ref origin/main --format markdown
```

## Installation

```bash
go install github.com/dovocoder/gollaw@latest
```

## License

MIT

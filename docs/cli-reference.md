# CLI Reference

## `gollaw analyze [patterns...]`

Run analysis on the codebase.

```bash
gollaw analyze .                  # analyze current directory
gollaw analyze ./internal/...     # analyze specific packages
gollaw analyze . -a deadcode      # run only deadcode analyzer
gollaw analyze . --format json    # JSON output
gollaw analyze . --no-suppress    # show all findings (ignore suppressions)
gollaw analyze . --baseline       # show only new findings vs baseline
```

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--format` | `-f` | `text` | `text`, `json`, `sarif`, `markdown` |
| `--analyzers` | `-a` | all | Comma-separated analyzer names |
| `--dir` | | `.` | Working directory |
| `--rule` | | | Architecture rule: `"pkg must not import other"` |
| `--min-severity` | | `warning` | `critical`, `warning`, `info`, `hint` |
| `--max-cyclomatic` | | `15` | Max cyclomatic complexity threshold |
| `--max-cognitive` | | `20` | Max cognitive complexity threshold |
| `--min-dup-lines` | | `5` | Min lines for duplication detection |
| `--no-config` | | | Ignore `.gollaw.yaml` |
| `--no-suppress` | | | Ignore suppression comments |
| `--baseline` | | | Show only new findings |

**Exit code:** `1` if any critical findings, `0` otherwise.

---

## `gollaw health`

Show the overall health score and breakdown by category.

```bash
gollaw health
gollaw health --dir /path/to/project
```

---

## `gollaw file-scores`

Show per-file health scores ranked from worst to best.

```bash
gollaw file-scores
```

---

## `gollaw audit`

Run a PR audit comparing findings against a base branch.

```bash
gollaw audit --base-ref origin/main
gollaw audit --base-ref origin/main --format markdown
gollaw audit --base-ref origin/main --dir .
```

| Flag | Default | Description |
|------|---------|-------------|
| `--base-ref` | `origin/main` | Git base reference |
| `--format` | `text` | `text`, `json`, `markdown` |
| `--dir` | `.` | Working directory |

**Exit code:** `1` if verdict is `fail`, `0` if `pass`.

---

## `gollaw guard <subcommand>`

Architecture guard rules.

```bash
gollaw guard list                    # list configured rules
gollaw guard check <file>            # check a file against rules
```

---

## `gollaw explain <symbol>`

Explain why a symbol is flagged as dead or unused.

```bash
gollaw explain MyFunction
gollaw explain (*Handler).ServeHTTP
```

---

## `gollaw trace <symbol>`

Trace the call graph for a symbol.

```bash
gollaw trace MyFunction                          # trace callers (default)
gollaw trace MyFunction --direction callees      # trace callees
gollaw trace MyFunction --depth 5                # max depth
```

| Flag | Default | Description |
|------|---------|-------------|
| `--direction` | `callers` | `callers` or `callees` |
| `--depth` | `10` | Max traversal depth |
| `--dir` | `.` | Working directory |
| `--format` | `text` | `text` or `json` |

---

## `gollaw baseline <subcommand>`

Manage finding baselines for tracking new issues.

```bash
gollaw baseline save    # save current findings as baseline
gollaw baseline diff    # show new findings since baseline
gollaw baseline show    # show saved baseline
```

---

## `gollaw trends <subcommand>`

Track health score over time.

```bash
gollaw trends --save    # save a health snapshot
gollaw trends           # show trend history
```

---

## `gollaw vital-signs`

Show a project overview: files, packages, functions, findings by severity, health score.

```bash
gollaw vital-signs
```

---

## `gollaw targets`

Show refactoring targets ranked by finding count and severity.

```bash
gollaw targets
```

---

## `gollaw coverage`

Identify functions with no test coverage.

```bash
gollaw coverage
```

---

## `gollaw public-api`

Analyze the exported API surface.

```bash
gollaw public-api
```

---

## `gollaw xref`

Cross-reference findings that reference the same symbol.

```bash
gollaw xref
```

---

## `gollaw inspect <file|symbol>`

Inspect a file or symbol in detail.

```bash
gollaw inspect main.go
gollaw inspect MyFunction
```

---

## `gollaw impact <file>`

Show the blast radius of changes to a file.

```bash
gollaw impact main.go
```

---

## `gollaw walkthrough`

Generate a guided, step-by-step refactoring plan.

```bash
gollaw walkthrough
```

---

## `gollaw timings`

Show how long each analyzer takes.

```bash
gollaw timings
```

---

## `gollaw init [dir]`

Create a `.gollaw.yaml` configuration file.

```bash
gollaw init .          # create in current directory
gollaw init /my/project
```

---

## `gollaw fix [flags]`

Auto-fix findings.

```bash
gollaw fix --dry-run               # preview fixes
gollaw fix --analyzer deadcode     # fix only deadcode findings
gollaw fix --apply                 # apply fixes
```

| Flag | Default | Description |
|------|---------|-------------|
| `--dry-run` | `true` | Preview without applying |
| `--analyzer` | all | Only fix findings from this analyzer |
| `--apply` | `false` | Apply fixes to disk |

---

## `gollaw migrate <subcommand>`

Migrate configuration from other tools.

```bash
gollaw migrate --check               # check what can be migrated
gollaw migrate staticcheck             # migrate staticcheck config
gollaw migrate golangci-lint           # migrate golangci-lint config
```

---

## `gollaw rule-pack`

List available pre-built architecture rule packs.

```bash
gollaw rule-pack
```

---

## `gollaw list`

List all available analyzers.

```bash
gollaw list
```

---

## `gollaw version`

Show version information.

```bash
gollaw version
```

---

## `gollaw lsp`

Start the LSP server for editor integration.

```bash
gollaw lsp
```

---

## `gollaw mcp`

Start the MCP server for AI agent integration.

```bash
gollaw mcp
```

---

## `gollaw watch`

Watch for file changes and re-run analysis.

```bash
gollaw watch
```

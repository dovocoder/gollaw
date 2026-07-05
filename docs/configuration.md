# Configuration

Gollaw is configured via a `.gollaw.yaml` file in the project root. Generate one with:

```bash
gollaw init .
```

## Full Configuration Reference

```yaml
# .gollaw.yaml
# Gollaw configuration

# Analyzer selection
analyzers:
  enabled: []          # empty = all analyzers
  disabled: []         # e.g. ["churn", "feature-flags"]

# Architecture rules
rules:
  - "internal/handler must not import internal/storage"
  - "internal/cli must not import internal/mcp"
  - "cmd must not import internal/storage"

# Severity overrides (override default severity per rule ID)
severity:
  GLW-CC001: warning   # complexity → warning (default: warning)
  GLW-LF001: info      # large-functions → info (default: info)
  GLW-DP001: warning   # duplication → warning (default: warning)

# Complexity thresholds
thresholds:
  max-cyclomatic: 15   # max cyclomatic complexity (default: 15)
  max-cognitive: 20    # max cognitive complexity (default: 20)
  min-dup-lines: 5    # min lines for duplication (default: 5)
  max-function-lines: 50  # max lines per function (default: 50)

# Suppressions (file-level, in addition to inline comments)
suppress:
  - file: "internal/legacy/"
    analyzer: "*"       # suppress all analyzers
  - file: "testdata/"
    analyzer: "naming"  # suppress only naming
```

## Analyzer Selection

### Enable specific analyzers

```yaml
analyzers:
  enabled: [deadcode, complexity, duplication]
```

This runs **only** the listed analyzers.

### Disable specific analyzers

```yaml
analyzers:
  disabled: [churn, feature-flags, dead-flags]
```

This runs all analyzers **except** the listed ones.

### Default (all analyzers)

```yaml
analyzers:
  enabled: []
  disabled: []
```

## Architecture Rules

Rules are defined as strings in the format `"package must not import other-package"`:

```yaml
rules:
  # Handler layer must not directly access storage
  - "internal/handler must not import internal/storage"

  # CLI must not depend on MCP server
  - "internal/cli must not import internal/mcp"

  # Entry point must not import storage
  - "cmd must not import internal/storage"
```

Rules match on package import path prefixes. A rule `"internal/handler must not import internal/storage"` will flag any file in `internal/handler/` that imports anything under `internal/storage/`.

## Severity Overrides

Each analyzer has a default severity. You can override it by rule ID:

```yaml
severity:
  GLW-CC001: critical   # treat complexity as critical
  GLW-LF001: hint        # treat large functions as hint only
```

| Rule ID | Analyzer | Default |
|---------|---------|---------|
| GLW-DC001 | deadcode | warning |
| GLW-U001 | unused | info |
| GLW-CC001 | complexity | warning |
| GLW-DP001 | duplication | warning |
| GLW-DE001 | dependencies | warning |
| GLW-AR001 | architecture | critical |
| GLW-UD001 | unused-deps | warning |
| GLW-LF001 | large-functions | info |
| GLW-HS001 | hotspots | warning |
| GLW-SC001 | security | critical |
| GLW-NM001 | naming | info |
| GLW-UF001 | unused-files | warning |
| GLW-TW001 | thin-wrappers | info |
| GLW-CH001 | churn | info |
| GLW-BC001 | boundary-coverage | info |
| GLW-FF001 | feature-flags | info |
| GLW-UM001 | unused-members | info |
| GLW-RC001 | re-export-cycles | warning |
| GLW-UO001 | unused-overrides | info |
| GLW-DF001 | dead-flags | warning |
| GLW-AS001 | api-surface | info |

## Thresholds

```yaml
thresholds:
  max-cyclomatic: 15      # Functions with higher cyclomatic complexity are flagged
  max-cognitive: 20       # Functions with higher cognitive complexity are flagged
  min-dup-lines: 5        # Minimum block size for duplication detection
  max-function-lines: 50  # Functions longer than this are flagged
```

These can also be set via CLI flags (`--max-cyclomatic`, `--max-cognitive`, `--min-dup-lines`).

## File-Level Suppressions

In addition to inline `//gollaw:keep` comments, you can suppress findings for entire directories:

```yaml
suppress:
  - file: "internal/legacy/"
    analyzer: "*"
  - file: "testdata/"
    analyzer: "naming"
  - file: "internal/generated/"
    analyzer: "*"
```

## CLI Override

CLI flags override config file settings:

```bash
# Config file has max-cyclomatic: 15, but CLI overrides to 20
gollaw analyze . --max-cyclomatic 20

# Config file has enabled: [deadcode], but CLI runs all
gollaw analyze . --no-config

# Config file has suppressions, but CLI ignores them
gollaw analyze . --no-suppress
```

## Example Configurations

### Minimal (defaults)

```yaml
# .gollaw.yaml
analyzers:
  enabled: []
  disabled: []
```

### Strict (all warnings as critical)

```yaml
analyzers:
  disabled: [churn]

severity:
  GLW-CC001: critical
  GLW-LF001: warning
  GLW-DP001: critical

thresholds:
  max-cyclomatic: 10
  max-cognitive: 15
  max-function-lines: 40
```

### Legacy codebase (lenient)

```yaml
analyzers:
  enabled: [deadcode, unused, unused-deps, security]

thresholds:
  max-cyclomatic: 25
  max-cognitive: 30
  max-function-lines: 100

suppress:
  - file: "internal/legacy/"
    analyzer: "*"
  - file: "vendor/"
    analyzer: "*"
```

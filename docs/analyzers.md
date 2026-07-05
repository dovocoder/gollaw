# Analyzers

Gollaw includes 21 analyzers that run on every `analyze` command.

## Dead Code & Unused

### deadcode (GLW-DC001)

Detects unreachable functions using SSA instruction analysis.

- **Method:** Starts from entry points (exported functions, `main`, `init`), walks SSA instructions following `StaticCallee`, `Call`, `Go`, `Defer`, and `MakeClosure`.
- **Severity:** `warning`
- **Fix:** Remove the function or add a caller. If used via reflection or interface dispatch, add `//gollaw:keep`.

```go
// This function is never called → deadcode finding
func unusedHelper() string { return "hello" }
```

### unused (GLW-U001)

Detects exported types, functions, variables, and constants that are never referenced outside their defining package.

- **Method:** Cross-references all exported symbols across loaded packages.
- **Severity:** `info`
- **Fix:** Unexport the symbol (rename to lowercase) if it's internal.

### unused-deps (GLW-UD001)

Finds dependencies in `go.mod` that are never imported by any package.

- **Severity:** `warning`
- **Fix:** Run `go mod tidy`.

### unused-files (GLW-UF001)

Finds Go files that are not part of any loaded package (orphaned files).

- **Severity:** `warning`
- **Fix:** Delete the file or add a build tag.

### unused-members (GLW-UM001)

Finds struct fields that are never read or written.

- **Severity:** `info`
- **Fix:** Remove the field.

### unused-overrides (GLW-UO001)

Finds interface method implementations that are never called via the interface.

- **Severity:** `info`

---

## Complexity & Size

### complexity (GLW-CC001)

Detects functions with high cyclomatic or cognitive complexity.

- **Cyclomatic:** Number of linearly independent paths (if/else/for/switch/case).
- **Cognitive:** How hard it is for a human to understand (nesting adds weight).
- **Thresholds:** `--max-cyclomatic 15`, `--max-cognitive 20`
- **Severity:** `warning`
- **Fix:** Extract helper functions, reduce nesting, use early returns.

### large-functions (GLW-LF001)

Flags functions exceeding 50 lines (excluding blank lines and comments).

- **Threshold:** `--max-function-lines 50` (configurable)
- **Severity:** `info`
- **Fix:** Split into smaller, focused functions.

### hotspots (GLW-HS001)

Identifies files with high complexity density (total complexity / number of functions).

- **Severity:** `warning`
- **Fix:** Split the file or refactor complex functions.

### thin-wrappers (GLW-TW001)

Detects functions that only delegate to a single other function (one-line wrappers).

- **Severity:** `info`
- **Fix:** Inline the wrapper or remove it.

---

## Duplication

### duplication (GLW-DP001)

Finds duplicate code blocks using AST structural hashing.

- **Method:** Hashes AST node sequences and finds matches across files.
- **Threshold:** `--min-dup-lines 5` (minimum block size)
- **Severity:** `warning`
- **Fix:** Extract the duplicated logic into a shared helper function.

---

## Architecture

### architecture (GLW-AR001)

Checks architecture boundary rules defined via `--rule` flags or `.gollaw.yaml`.

- **Rule format:** `"package must not import other-package"`
- **Severity:** `critical`
- **Fix:** Remove the forbidden import or restructure the dependency.

```bash
gollaw analyze . --rule "internal/handler must not import internal/storage"
```

### dependencies (GLW-DE001)

Analyzes the import graph for cycles and dependency hygiene issues.

- **Severity:** `warning`
- **Fix:** Break the cycle by extracting a shared package.

### boundary-coverage (GLW-BC001)

Finds exported functions that lack boundary tests (tests that exercise the function through its public API).

- **Severity:** `info`
- **Fix:** Add a test for the exported function.

### re-export-cycles (GLW-RC001)

Finds re-export chains that form cycles (A re-exports B, B re-exports A).

- **Severity:** `warning`

---

## Security

### security (GLW-SC001)

Detects security issues:

- Hardcoded secrets (API keys, passwords, tokens)
- `TODO`/`FIXME` comments
- `unsafe` package usage
- SQL injection patterns
- Weak crypto usage

- **Severity:** `critical` (secrets), `warning` (unsafe), `info` (TODOs)
- **Fix:** Move secrets to environment variables, replace unsafe code, resolve TODOs.

---

## Code Quality

### naming (GLW-NM001)

Checks Go naming conventions:

- Exported identifiers should be `CamelCase`
- Unexported identifiers should be `camelCase`
- Acronyms should be uppercase (`HTTP`, `URL`, `API`)
- Interface names should not have `I` prefix

- **Severity:** `info`
- **Fix:** Rename the identifier.

### api-surface (GLW-AS001)

Finds exported symbols that are only used within their own package — they should be unexported.

- **Severity:** `info`
- **Fix:** Unexport the symbol (rename to lowercase).

### feature-flags (GLW-FF001)

Finds hardcoded feature flag values (boolean constants used as feature toggles).

- **Severity:** `info`
- **Fix:** Move to configuration or environment variables.

### dead-flags (GLW-DF001)

Finds feature flags that are always `true` or always `false`.

- **Severity:** `warning`
- **Fix:** Remove the dead flag and its conditional code.

---

## Maintenance

### churn (GLW-CH001)

Identifies files with high git commit churn (frequent changes).

- **Method:** Counts commits per file over the last 6 months.
- **Threshold:** Files with ≥10 changes
- **Severity:** `info`
- **Fix:** Split the file, add more tests, or stabilize the interface.

---

## Selecting Analyzers

```bash
# Run only specific analyzers
gollaw analyze . -a deadcode,complexity

# List all analyzers
gollaw list

# Disable analyzers in config
# .gollaw.yaml:
# analyzers:
#   disabled: [churn, feature-flags]
```

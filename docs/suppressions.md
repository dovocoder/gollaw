# Suppression Comments

Gollaw supports inline suppression comments to control which findings are reported.

## `//gollaw:keep`

Suppresses **all** analyzers on the declaration it precedes.

```go
//gollaw:keep
func legacyHandler(w http.ResponseWriter, r *http.Request) {
    // This function is used via reflection — deadcode can't trace it
}
```

Works on:
- Functions
- Methods
- Types
- Variables
- Constants
- Package declarations (file-level)

## `//gollaw:ignore <analyzer>`

Suppresses a **specific** analyzer on the declaration.

```go
//gollaw:ignore api-surface
func PublicAPI() {
    // Intentionally exported — used by external callers not in this module
}

//gollaw:ignore deadcode
func parseArgs[T any](args json.RawMessage) T {
    // Generic function — called via type parameters which deadcode can't trace
}
```

Supported analyzers: `deadcode`, `unused`, `complexity`, `duplication`, `dependencies`,
`architecture`, `unused-deps`, `large-functions`, `hotspots`, `security`, `naming`,
`unused-files`, `thin-wrappers`, `churn`, `boundary-coverage`, `feature-flags`,
`unused-members`, `re-export-cycles`, `unused-overrides`, `dead-flags`, `api-surface`.

## `//gollaw:ignore-all`

Suppresses **all** analyzers for the entire file.

```go
//gollaw:ignore-all
package legacy

// All findings in this file are suppressed
```

## Placement

Suppression comments must be on the line directly **before** the declaration:

```go
// ✅ Correct — comment is directly before func
//gollaw:keep
func MyFunction() {}

// ❌ Wrong — blank line between comment and func
//gollaw:keep

func MyFunction() {}
```

For struct fields:

```go
type Config struct {
    //gollaw:ignore unused-members
    InternalField string  // used via reflection
}
```

## File-Level Suppression via Config

You can also suppress findings for entire directories via `.gollaw.yaml`:

```yaml
suppress:
  - file: "internal/legacy/"
    analyzer: "*"
  - file: "testdata/"
    analyzer: "naming"
```

## Disabling Suppression

To see all findings regardless of suppression comments:

```bash
gollaw analyze . --no-suppress
```

This is useful for auditing which suppressions are in place:

```bash
# Count suppressions
gollaw analyze . --no-suppress --format json | jq '[.findings[] | select(.suppressed == true)] | length'
```

## Best Practices

1. **Prefer fixing over suppressing** — suppressions hide real issues
2. **Use `//gollaw:ignore <analyzer>` over `//gollaw:keep`** — targeted suppression is safer
3. **Add a comment explaining why** — future maintainers need context
4. **Review suppressions regularly** — `gollaw analyze . --no-suppress` to audit
5. **Avoid `//gollaw:ignore-all`** — it's a sledgehammer; prefer per-declaration comments

```go
// ✅ Good: targeted with explanation
//gollaw:ignore deadcode
// parseArgs is a generic function — called via type parameters
func parseArgs[T any](args json.RawMessage) T { ... }

// ❌ Bad: blanket suppression, no explanation
//gollaw:keep
func mysteryFunction() { ... }
```

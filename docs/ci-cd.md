# CI/CD Integration

## GitHub Actions

### Basic audit on PRs

```yaml
# .github/workflows/gollaw.yml
name: gollaw
on:
  pull_request:
    branches: [main, master]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0    # need full history for git diff

      - uses: actions/setup-go@v5
        with:
          go-version: '1.25'

      - name: Install Gollaw
        run: go install github.com/dovocoder/gollaw@latest

      - name: Run audit
        run: gollaw audit --base-ref origin/main --format markdown
```

### With SARIF upload

```yaml
name: gollaw
on: [push, pull_request]

jobs:
  analyze:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write    # needed for SARIF upload
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: actions/setup-go@v5
        with:
          go-version: '1.25'

      - run: go install github.com/dovocoder/gollaw@latest

      - name: Analyze
        run: gollaw analyze . --format sarif -o results.sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### Block PRs on critical findings

```yaml
- name: Check for critical findings
  run: |
    gollaw analyze . --format json | jq '.findings[] | select(.severity == "critical")' > /dev/null
    if [ $? -eq 0 ]; then
      echo "Critical findings detected — blocking PR"
      exit 1
    fi
```

### Using prebuilt binary

```yaml
- name: Install Gollaw
  run: |
    curl -L https://github.com/dovocoder/gollaw/releases/latest/download/gollaw-v0.2.0-linux-amd64.tar.gz | tar xz
    sudo mv gollaw /usr/local/bin/
```

## Pre-commit Hook

### Using pre-commit framework

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: gollaw
        name: gollaw
        entry: gollaw analyze .
        language: system
        pass_filenames: false
        types: [go]
```

### Using git hooks directly

```bash
# .git/hooks/pre-commit
#!/bin/bash
gollaw analyze . --min-severity warning
```

```bash
chmod +x .git/hooks/pre-commit
```

## GitLab CI

```yaml
# .gitlab-ci.yml
gollaw:
  stage: test
  image: golang:1.25
  script:
    - go install github.com/dovocoder/gollaw@latest
    - gollaw analyze . --format json
  rules:
    - if: $CI_MERGE_REQUEST_ID
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No critical findings |
| 1 | Critical findings present, or audit verdict: fail |

Use `--min-severity` to control what counts as a failure:

```bash
# Fail on warnings or higher
gollaw analyze . --min-severity warning

# Fail only on critical
gollaw analyze . --min-severity critical
```

## Baseline Strategy

Use baselines to avoid failing CI on pre-existing findings:

```bash
# On main branch: save baseline
gollaw baseline save
git add .gollaw-baseline.json
git commit -m "chore: update gollaw baseline"

# On PR branch: only new findings cause failure
gollaw analyze . --baseline --min-severity warning
```

## Docker

```dockerfile
FROM golang:1.25 AS gollaw
RUN go install github.com/dovocoder/gollaw@latest

FROM golang:1.25
COPY --from=gollaw /go/bin/gollaw /usr/local/bin/
COPY . /workspace
WORKDIR /workspace
RUN gollaw analyze .
```

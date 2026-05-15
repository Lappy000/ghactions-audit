# ghactions-audit

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Static analysis tool for GitHub Actions workflow files. Detects security misconfigurations including unpinned actions, script injection, dangerous triggers, OIDC token issues, cache poisoning vectors, and more. Outputs table, JSON, Markdown, or [SARIF](https://sarifweb.azurewebsites.net/) for GitHub Code Scanning integration.

## Install

```bash
pip install -e .
```

Or run directly:

```bash
pip install -r requirements.txt
python -m ghactions_audit /path/to/repo
```

## Usage

```bash
# Scan current directory
ghactions-audit .

# Scan a specific repo
ghactions-audit /path/to/repo

# Scan a single workflow file
ghactions-audit .github/workflows/ci.yml

# JSON output for CI pipelines
ghactions-audit . --format json

# SARIF output for GitHub Code Scanning
ghactions-audit . --format sarif > results.sarif

# Markdown output (for PR review comments)
ghactions-audit . --format markdown

# Only show high and critical
ghactions-audit . --severity high

# Ignore specific rules
ghactions-audit . --ignore GHA006 --ignore GHA008

# Use a specific config file
ghactions-audit . --config .ghactions-audit.yml

# Auto-fix unpinned actions (resolve tags to SHA)
ghactions-audit . --fix

# Preview what --fix would change
ghactions-audit . --fix-dry-run

# List all rules
ghactions-audit . --list-rules

# Don't fail CI on findings
ghactions-audit . --no-exit-code
```

## Rules

| ID | Default Severity | Description |
|----|-----------------|-------------|
| GHA001 | high | Actions pinned to mutable tags instead of commit SHA |
| GHA002 | critical | Dangerous triggers (`pull_request_target`, `workflow_run`) |
| GHA003 | high | Overly permissive `GITHUB_TOKEN` permissions |
| GHA004 | critical | Script injection via attacker-controlled context expressions |
| GHA005 | high | Secret values potentially exposed in workflow logs |
| GHA006 | low | Third-party actions from non-verified organizations |
| GHA007 | high | Self-hosted runners exposed to untrusted code triggers |
| GHA008 | medium | Unsafe execution defaults (`continue-on-error`) |
| GHA009 | medium | Artifact upload/download trust boundary issues |
| GHA010 | critical | Environment variable injection via `GITHUB_ENV`/`GITHUB_PATH` |
| GHA011 | high | Cache poisoning risk on PR-triggered workflows |
| GHA012 | high | OIDC token (`id-token: write`) misconfiguration |
| GHA013 | critical | Script injection via `actions/github-script` with untrusted inputs |
| GHA014 | high | Unsafe `workflow_dispatch` inputs interpolated into shell commands |
| GHA015 | critical | Secrets accessible in jobs triggered by untrusted events |

## Configuration

Create `.ghactions-audit.yml` in your repo root:

```yaml
# Rules to disable entirely
ignore:
  - GHA006
  - GHA008

# Minimum severity threshold
severity: medium

# File patterns to skip
ignore_paths:
  - ".github/workflows/legacy-*.yml"

# Additional trusted action orgs (extends built-in list)
trusted_orgs:
  - my-company
  - my-other-org

# Actions allowed to use mutable tags (skip GHA001)
allow_unpinned:
  - actions/checkout
  - actions/setup-python

# Per-rule overrides
rules:
  GHA006:
    severity: medium   # Bump third-party action findings
  GHA008:
    enabled: false     # Disable entirely
```

## Auto-Fix

The `--fix` flag resolves mutable action tag references to pinned commit SHAs via the GitHub API:

```bash
# Set token for higher API rate limits (optional but recommended)
export GITHUB_TOKEN=ghp_...

# Preview changes
ghactions-audit . --fix-dry-run

# Apply fixes
ghactions-audit . --fix
```

Before:
```yaml
- uses: actions/checkout@v4
- uses: actions/setup-node@v4
```

After:
```yaml
- uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4
- uses: actions/setup-node@60edb5dd545a775178f52524783378180af0d1f8  # v4
```

## SARIF / GitHub Code Scanning

Upload results to GitHub's Security tab:

```yaml
- name: Audit workflows
  run: |
    pip install ghactions-audit
    ghactions-audit . --format sarif --no-exit-code > results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## Output Formats

### Table (default)

```
┌──────┬─────────┬──────────────────┬──────┬───────────────────────────────────────────┐
│ Sev  │ Rule    │ File             │   Ln │ Issue                                     │
├──────┼─────────┼──────────────────┼──────┼───────────────────────────────────────────┤
│ CRIT │ GHA004  │ .../ci.yml       │   23 │ Expression '${{ github.event.issue.tit... │
│ CRIT │ GHA010  │ .../ci.yml       │   25 │ Writes attacker-controlled data to GIT... │
│ HIGH │ GHA001  │ .../ci.yml       │   15 │ Action 'actions/checkout@v4' is pinned... │
│ HIGH │ GHA011  │ .../deploy.yml   │   42 │ Cache key may not be branch-scoped...     │
└──────┴─────────┴──────────────────┴──────┴───────────────────────────────────────────┘
```

### JSON

```json
{
  "total": 4,
  "findings": [
    {
      "rule_id": "GHA004",
      "severity": "critical",
      "file": ".github/workflows/ci.yml",
      "line": 23,
      "title": "Potential script injection",
      "description": "...",
      "remediation": "..."
    }
  ]
}
```

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No findings at or above the minimum severity |
| `1` | Findings detected (or `--no-exit-code` to override) |

## Running Tests

```bash
pip install pytest
pytest tests/ -v
```

## License

MIT

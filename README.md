# ghactions-audit

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

CLI tool that audits GitHub Actions workflow files for security misconfigurations. Checks for unpinned actions, dangerous triggers, script injection vectors, overly permissive tokens, and more.

## Install

```bash
pip install -e .
```

Or just use directly:

```bash
pip install -r requirements.txt
python -m ghactions_audit.cli /path/to/repo
```

## Usage

```bash
# Scan current directory
ghactions-audit .

# Scan a specific repo
ghactions-audit /path/to/repo

# Scan a single workflow file
ghactions-audit .github/workflows/ci.yml

# JSON output for CI integration
ghactions-audit . --format json

# Markdown output (for PR comments)
ghactions-audit . --format markdown

# Only show high and critical
ghactions-audit . --severity high

# Ignore specific rules
ghactions-audit . --ignore GHA006 --ignore GHA008

# Don't fail CI on findings
ghactions-audit . --no-exit-code
```

## Rules

| ID | Severity | Description |
|----|----------|-------------|
| GHA001 | high | Actions pinned to mutable tags instead of SHA |
| GHA002 | critical | Dangerous triggers (pull_request_target, workflow_run) |
| GHA003 | high | Overly permissive GITHUB_TOKEN permissions |
| GHA004 | critical | Script injection via attacker-controlled expressions |
| GHA005 | high | Secret values potentially exposed in logs |
| GHA006 | low | Third-party actions from non-verified orgs |
| GHA007 | high | Self-hosted runners with untrusted code triggers |
| GHA008 | medium | Unsafe execution defaults (continue-on-error) |
| GHA009 | medium | Artifact upload/download trust boundary issues |

## Output Formats

### Table (default)

```
┌──────┬─────────┬──────────────────┬──────┬─────────────────────────────────────────┐
│ Sev  │ Rule    │ File             │   Ln │ Issue                                   │
├──────┼─────────┼──────────────────┼──────┼─────────────────────────────────────────┤
│ CRIT │ GHA004  │ .../ci.yml       │   23 │ Expression '${{ github.event.issue...   │
│ HIGH │ GHA001  │ .../ci.yml       │   15 │ Action 'actions/checkout@v4' is pin...  │
└──────┴─────────┴──────────────────┴──────┴─────────────────────────────────────────┘
```

### JSON

```json
{
  "total": 2,
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

## CI Integration

Add to your workflow:

```yaml
- name: Audit workflows
  run: |
    pip install ghactions-audit
    ghactions-audit . --severity medium --format json > audit-results.json
```

## Exit Codes

- `0` — No findings (or `--no-exit-code` flag used)
- `1` — Findings detected

## License

MIT

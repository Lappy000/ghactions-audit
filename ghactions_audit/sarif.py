"""SARIF output format for GitHub Code Scanning integration.

Produces SARIF v2.1.0 compatible output that can be uploaded to
GitHub's code scanning results via the upload-sarif action.
"""

import json
from typing import List

from .scanner import Finding


SARIF_VERSION = "2.1.0"
SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"
TOOL_NAME = "ghactions-audit"
TOOL_VERSION = "0.1.0"
TOOL_URI = "https://github.com/Lappy000/ghactions-audit"

SEVERITY_TO_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}


def render_sarif(findings: List[Finding]) -> str:
    """Render findings as a SARIF JSON string.

    Compatible with:
      - GitHub Code Scanning (upload-sarif action)
      - VS Code SARIF viewer
      - Azure DevOps
    """
    rules = _build_rules(findings)
    results = _build_results(findings)

    sarif = {
        "$schema": SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": TOOL_VERSION,
                        "informationUri": TOOL_URI,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }

    return json.dumps(sarif, indent=2)


def _build_rules(findings: List[Finding]) -> list:
    """Build SARIF rule descriptors from unique rule IDs in findings."""
    seen = {}
    rules = []

    for f in findings:
        if f.rule_id in seen:
            continue
        seen[f.rule_id] = True
        rules.append({
            "id": f.rule_id,
            "name": f.title,
            "shortDescription": {"text": f.title},
            "fullDescription": {"text": f.description},
            "defaultConfiguration": {
                "level": SEVERITY_TO_SARIF_LEVEL.get(f.severity, "warning")
            },
            "helpUri": f"{TOOL_URI}#rules",
            "properties": {
                "security-severity": _security_severity_score(f.severity),
            },
        })

    return rules


def _build_results(findings: List[Finding]) -> list:
    """Build SARIF result objects from findings."""
    results = []

    for f in findings:
        result = {
            "ruleId": f.rule_id,
            "level": SEVERITY_TO_SARIF_LEVEL.get(f.severity, "warning"),
            "message": {
                "text": f.description,
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": _normalize_path(f.file),
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": max(f.line, 1),
                        },
                    }
                }
            ],
            "fixes": [
                {
                    "description": {"text": f.remediation},
                }
            ] if f.remediation else [],
        }
        results.append(result)

    return results


def _normalize_path(filepath: str) -> str:
    """Normalize file path for SARIF (forward slashes, relative)."""
    path = filepath.replace("\\", "/")
    # Strip leading ./ if present
    if path.startswith("./"):
        path = path[2:]
    return path


def _security_severity_score(severity: str) -> str:
    """Map severity to CVSS-like score for GitHub security tab."""
    scores = {
        "critical": "9.5",
        "high": "7.5",
        "medium": "5.0",
        "low": "2.5",
    }
    return scores.get(severity, "5.0")

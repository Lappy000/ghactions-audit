"""Workflow file scanner that applies rules to parsed YAML."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml


@dataclass
class Finding:
    """A single security finding in a workflow file."""

    rule_id: str
    severity: str  # low, medium, high, critical
    file: str
    line: int
    title: str
    description: str
    remediation: str


@dataclass
class ScanContext:
    """Additional context passed to rules during scanning."""

    trusted_orgs: set[str] = field(default_factory=set)
    allow_unpinned: set[str] = field(default_factory=set)


class WorkflowScanner:
    """Scans GitHub Actions workflow files against a set of security rules."""

    def __init__(
        self,
        rules: list,
        ignore_rules: Optional[set[str]] = None,
        context: Optional[ScanContext] = None,
    ):
        self.rules = rules
        self.ignore_rules = ignore_rules or set()
        self.context = context or ScanContext()

    def scan_file(self, path: Path) -> list[Finding]:
        """Scan a single workflow YAML file and return findings."""
        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as e:
            return [
                Finding(
                    rule_id="PARSE001",
                    severity="low",
                    file=str(path),
                    line=0,
                    title="File read error",
                    description=f"Could not read file: {e}",
                    remediation="Check file permissions and encoding.",
                )
            ]

        try:
            workflow = yaml.safe_load(content)
        except yaml.YAMLError as e:
            return [
                Finding(
                    rule_id="PARSE002",
                    severity="low",
                    file=str(path),
                    line=0,
                    title="YAML parse error",
                    description=f"Invalid YAML: {e}",
                    remediation="Fix YAML syntax errors.",
                )
            ]

        if not isinstance(workflow, dict):
            return []

        findings = []
        lines = content.splitlines()

        for rule in self.rules:
            if rule.rule_id in self.ignore_rules:
                continue
            rule_findings = rule.check(workflow, lines, str(path))
            findings.extend(rule_findings)

        return findings

    def scan_directory(self, directory: Path) -> list[Finding]:
        """Scan all workflow files in a .github/workflows/ directory."""
        workflows_dir = directory / ".github" / "workflows"
        if not workflows_dir.exists():
            return []

        findings = []
        for pattern in ("*.yml", "*.yaml"):
            for wf_file in sorted(workflows_dir.glob(pattern)):
                findings.extend(self.scan_file(wf_file))

        return findings

    def get_stats(self, findings: list[Finding]) -> dict[str, int]:
        """Aggregate finding counts by severity."""
        counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

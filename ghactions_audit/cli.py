"""CLI entry point for ghactions-audit."""

import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table

from .scanner import WorkflowScanner
from .rules import get_all_rules
from .report import render_report, render_json_report

console = Console()


@click.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--format", "-f", "output_format", type=click.Choice(["table", "json", "markdown"]), default="table", help="Output format")
@click.option("--severity", "-s", type=click.Choice(["low", "medium", "high", "critical"]), default=None, help="Minimum severity to report")
@click.option("--ignore", "-i", multiple=True, help="Rule IDs to ignore (can specify multiple)")
@click.option("--exit-code/--no-exit-code", default=True, help="Return non-zero exit code on findings")
def main(path: str, output_format: str, severity: Optional[str], ignore: tuple, exit_code: bool) -> None:
    """Audit GitHub Actions workflows for security misconfigurations.

    PATH can be a directory containing .github/workflows/ or a single YAML file.
    """
    target = Path(path)
    scanner = WorkflowScanner(rules=get_all_rules(), ignore_rules=set(ignore))

    if target.is_file():
        workflow_files = [target]
    else:
        workflows_dir = target / ".github" / "workflows"
        if not workflows_dir.exists():
            console.print(f"[red]No .github/workflows/ directory found in {target}[/red]")
            sys.exit(1)
        workflow_files = list(workflows_dir.glob("*.yml")) + list(workflows_dir.glob("*.yaml"))

    if not workflow_files:
        console.print("[yellow]No workflow files found.[/yellow]")
        sys.exit(0)

    findings = []
    for wf in workflow_files:
        findings.extend(scanner.scan_file(wf))

    # Filter by severity if specified
    severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    if severity:
        min_level = severity_order[severity]
        findings = [f for f in findings if severity_order[f.severity] >= min_level]

    if output_format == "json":
        render_json_report(findings)
    elif output_format == "markdown":
        render_report(findings, fmt="markdown")
    else:
        render_report(findings, fmt="table")

    if exit_code and findings:
        sys.exit(1)


if __name__ == "__main__":
    main()

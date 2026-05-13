"""CLI entry point for ghactions-audit."""

import os
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console

from .scanner import WorkflowScanner
from .rules import get_all_rules
from .report import render_report, render_json_report
from .sarif import render_sarif
from .config import Config

console = Console()

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


@click.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option(
    "--format", "-f", "output_format",
    type=click.Choice(["table", "json", "markdown", "sarif"]),
    default="table",
    help="Output format.",
)
@click.option(
    "--severity", "-s",
    type=click.Choice(["low", "medium", "high", "critical"]),
    default=None,
    help="Minimum severity to report.",
)
@click.option(
    "--ignore", "-i",
    multiple=True,
    help="Rule IDs to ignore (can be specified multiple times).",
)
@click.option(
    "--config", "-c", "config_path",
    type=click.Path(exists=True),
    default=None,
    help="Path to config file (default: .ghactions-audit.yml in target dir).",
)
@click.option(
    "--fix",
    is_flag=True,
    default=False,
    help="Auto-fix unpinned actions by resolving to SHA (requires network).",
)
@click.option(
    "--fix-dry-run",
    is_flag=True,
    default=False,
    help="Show what --fix would change without modifying files.",
)
@click.option(
    "--exit-code/--no-exit-code",
    default=True,
    help="Return non-zero exit code on findings.",
)
@click.option(
    "--list-rules",
    is_flag=True,
    default=False,
    help="List all available rules and exit.",
)
@click.version_option(version="0.1.0", prog_name="ghactions-audit")
def main(
    path: str,
    output_format: str,
    severity: Optional[str],
    ignore: tuple,
    config_path: Optional[str],
    fix: bool,
    fix_dry_run: bool,
    exit_code: bool,
    list_rules: bool,
) -> None:
    """Audit GitHub Actions workflows for security misconfigurations.

    PATH can be a directory containing .github/workflows/ or a single YAML file.
    """
    # Handle --list-rules
    if list_rules:
        _print_rules()
        sys.exit(0)

    target = Path(path)

    # Load config
    if config_path:
        config = Config._parse(Path(config_path))
    elif target.is_dir():
        config = Config.load(target)
    else:
        config = Config.load(target.parent)

    # Merge CLI ignores with config ignores
    all_ignores = config.ignore_rules | set(ignore)

    # Build scanner with config-aware rule filtering
    rules = get_all_rules()
    active_rules = [r for r in rules if config.is_rule_enabled(r.rule_id)]

    scanner = WorkflowScanner(rules=active_rules, ignore_rules=all_ignores)

    # Discover workflow files
    if target.is_file():
        workflow_files = [target]
    else:
        workflows_dir = target / ".github" / "workflows"
        if not workflows_dir.exists():
            console.print(f"[red]No .github/workflows/ directory found in {target}[/red]")
            sys.exit(1)
        workflow_files = sorted(
            list(workflows_dir.glob("*.yml")) + list(workflows_dir.glob("*.yaml"))
        )

    # Apply path ignores from config
    if config.ignore_paths:
        import fnmatch
        workflow_files = [
            wf for wf in workflow_files
            if not any(fnmatch.fnmatch(str(wf), pat) for pat in config.ignore_paths)
        ]

    if not workflow_files:
        console.print("[yellow]No workflow files found.[/yellow]")
        sys.exit(0)

    # Handle --fix / --fix-dry-run
    if fix or fix_dry_run:
        _handle_fix(workflow_files, dry_run=fix_dry_run)
        if not fix_dry_run:
            console.print("[green]Re-scanning after fixes...[/green]\n")

    # Scan
    findings = []
    for wf in workflow_files:
        findings.extend(scanner.scan_file(wf))

    # Apply severity overrides from config
    for f in findings:
        override = config.get_severity_override(f.rule_id)
        if override:
            f.severity = override

    # Filter by severity
    min_severity = severity or config.min_severity
    if min_severity:
        min_level = SEVERITY_ORDER.get(min_severity, 0)
        findings = [f for f in findings if SEVERITY_ORDER.get(f.severity, 0) >= min_level]

    # Render output
    if output_format == "json":
        render_json_report(findings)
    elif output_format == "sarif":
        print(render_sarif(findings))
    elif output_format == "markdown":
        render_report(findings, fmt="markdown")
    else:
        render_report(findings, fmt="table")

    if exit_code and findings:
        sys.exit(1)


def _handle_fix(workflow_files: list, dry_run: bool = False) -> None:
    """Run the auto-fixer on discovered workflow files."""
    from .fixer import fix_unpinned_actions, generate_diff

    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")

    for wf in workflow_files:
        if dry_run:
            diff = generate_diff(wf, token=token)
            if diff:
                console.print(f"[bold]{wf}[/bold]:")
                console.print(diff)
            else:
                console.print(f"[dim]{wf}: no changes needed[/dim]")
        else:
            fixes = fix_unpinned_actions(wf, token=token)
            if fixes:
                console.print(f"[green]{wf}:[/green]")
                for old_ref, new_ref, sha in fixes:
                    console.print(f"  {old_ref} -> {sha[:12]}...")
            else:
                console.print(f"[dim]{wf}: no fixes applied[/dim]")


def _print_rules() -> None:
    """Print all available rules in a table."""
    from rich.table import Table

    rules = get_all_rules()
    table = Table(title="Available Rules", show_lines=False)
    table.add_column("ID", style="bold")
    table.add_column("Severity", width=8)
    table.add_column("Title")
    table.add_column("Class")

    for rule in rules:
        table.add_row(
            rule.rule_id,
            rule.severity,
            rule.title,
            rule.__class__.__name__,
        )

    console.print(table)


if __name__ == "__main__":
    main()

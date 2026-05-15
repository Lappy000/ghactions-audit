"""Report rendering for audit findings."""

import json

from rich.console import Console
from rich.table import Table
from rich.text import Text

from .scanner import Finding

console = Console()

SEVERITY_COLORS = {
    "critical": "red bold",
    "high": "red",
    "medium": "yellow",
    "low": "blue",
}

SEVERITY_ICONS = {
    "critical": "CRIT",
    "high": "HIGH",
    "medium": "MED ",
    "low": "LOW ",
}


def render_report(findings: list[Finding], fmt: str = "table") -> None:
    """Render findings to stdout."""
    if not findings:
        console.print("[green]No security issues found.[/green]")
        return

    if fmt == "markdown":
        _render_markdown(findings)
    else:
        _render_table(findings)

    # Summary
    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    summary_parts = []
    for sev in ("critical", "high", "medium", "low"):
        if sev in counts:
            summary_parts.append(f"[{SEVERITY_COLORS[sev]}]{counts[sev]} {sev}[/]")
    console.print(f"\nTotal: {len(findings)} findings ({', '.join(summary_parts)})")


def _render_table(findings: list[Finding]) -> None:
    """Render findings as a rich table."""
    table = Table(title="GitHub Actions Security Audit", show_lines=True)
    table.add_column("Sev", width=4, justify="center")
    table.add_column("Rule", width=7)
    table.add_column("File", max_width=30)
    table.add_column("Ln", width=4, justify="right")
    table.add_column("Issue", min_width=40)

    for f in sorted(findings, key=lambda x: _sev_key(x.severity)):
        sev_style = SEVERITY_COLORS[f.severity]
        table.add_row(
            Text(SEVERITY_ICONS[f.severity], style=sev_style),
            f.rule_id,
            _truncate_path(f.file),
            str(f.line) if f.line else "-",
            f.description,
        )

    console.print(table)


def _render_markdown(findings: list[Finding]) -> None:
    """Render findings as Markdown for CI comments."""
    print("## GitHub Actions Security Audit\n")
    print(f"Found **{len(findings)}** issues.\n")
    print("| Severity | Rule | File | Line | Issue | Remediation |")
    print("|----------|------|------|------|-------|-------------|")
    for f in sorted(findings, key=lambda x: _sev_key(x.severity)):
        file_short = _truncate_path(f.file)
        print(
            f"| {f.severity.upper()} | {f.rule_id} | {file_short} | {f.line or '-'} | {f.description} | {f.remediation} |"
        )


def render_json_report(findings: list[Finding]) -> None:
    """Render findings as JSON."""
    output = {
        "total": len(findings),
        "findings": [
            {
                "rule_id": f.rule_id,
                "severity": f.severity,
                "file": f.file,
                "line": f.line,
                "title": f.title,
                "description": f.description,
                "remediation": f.remediation,
            }
            for f in findings
        ],
    }
    print(json.dumps(output, indent=2))


def _sev_key(severity: str) -> int:
    """Sort key: critical first."""
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return order.get(severity, 4)


def _truncate_path(path: str) -> str:
    """Shorten path for display."""
    parts = path.replace("\\", "/").split("/")
    if len(parts) > 3:
        return ".../" + "/".join(parts[-3:])
    return path

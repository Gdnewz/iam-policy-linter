"""Output. Two formats: a terminal table for humans, JSON for machines."""

from __future__ import annotations

import json

from rich.console import Console
from rich.table import Table

from .models import Finding

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
SEVERITY_STYLE = {"HIGH": "bold red", "MEDIUM": "yellow", "LOW": "cyan"}


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.policy_name))


def print_table(findings: list[Finding]) -> None:
    console = Console()
    if not findings:
        console.print("[green]No findings. Nice.[/green]")
        return

    table = Table(title=f"IAM findings ({len(findings)})")
    table.add_column("Severity")
    table.add_column("Check")
    table.add_column("Policy")
    table.add_column("Where")
    table.add_column("Message")

    for f in sort_findings(findings):
        table.add_row(
            f"[{SEVERITY_STYLE.get(f.severity, '')}]{f.severity}[/]",
            f.check,
            f.policy_name,
            f.resource,
            f.message,
        )
    console.print(table)


def to_json(findings: list[Finding]) -> str:
    return json.dumps([f.to_dict() for f in sort_findings(findings)], indent=2, default=str)

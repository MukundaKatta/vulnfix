"""Report generation for vulnerability scan results."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from vulnfix.models import Fix, ScanResult, Severity, Vulnerability


class ReportGenerator:
    """Generates formatted reports from scan results."""

    SEVERITY_COLORS = {
        Severity.CRITICAL: "bold red",
        Severity.HIGH: "red",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "blue",
        Severity.INFO: "dim",
    }

    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console()

    def print_summary(self, result: ScanResult) -> None:
        """Print a summary panel of scan results."""
        result.compute_summary()
        s = result.summary

        summary_text = Text()
        summary_text.append(f"Target: {result.target}\n")
        summary_text.append(f"Scan type: {result.scan_type}\n")
        summary_text.append(f"Total findings: {s['total']}\n\n")
        summary_text.append("Critical: ", style="bold red")
        summary_text.append(f"{s['critical']}  ")
        summary_text.append("High: ", style="red")
        summary_text.append(f"{s['high']}  ")
        summary_text.append("Medium: ", style="yellow")
        summary_text.append(f"{s['medium']}  ")
        summary_text.append("Low: ", style="blue")
        summary_text.append(f"{s['low']}  ")
        summary_text.append("Info: ", style="dim")
        summary_text.append(f"{s['info']}")

        self.console.print(Panel(summary_text, title="VULNFIX Scan Summary", border_style="bold cyan"))

    def print_vulnerabilities(self, vulns: list[Vulnerability]) -> None:
        """Print vulnerabilities in a formatted table."""
        if not vulns:
            self.console.print("[green]No vulnerabilities found.[/green]")
            return

        table = Table(title="Vulnerabilities", show_lines=True)
        table.add_column("ID", style="dim", width=16)
        table.add_column("Severity", width=10)
        table.add_column("CVSS", width=6, justify="right")
        table.add_column("Title", width=30)
        table.add_column("File", width=30)
        table.add_column("Line", width=5, justify="right")
        table.add_column("CWE", width=10)

        for v in vulns:
            sev_style = self.SEVERITY_COLORS.get(v.severity, "")
            table.add_row(
                v.id,
                Text(v.severity.value.upper(), style=sev_style),
                f"{v.cvss_score:.1f}",
                v.title,
                str(v.file_path or "-"),
                str(v.line_number or "-"),
                v.cwe_id or "-",
            )

        self.console.print(table)

    def print_fixes(self, fixes: list[Fix]) -> None:
        """Print fix suggestions."""
        if not fixes:
            return

        self.console.print("\n[bold cyan]Fix Suggestions[/bold cyan]\n")
        for fix in fixes:
            self.console.print(f"[bold]{fix.vulnerability_id}[/bold]: {fix.title}")
            self.console.print(f"  {fix.description}")
            if fix.steps:
                for step in fix.steps:
                    self.console.print(f"    - {step}")
            if fix.original_code and fix.fixed_code:
                self.console.print(f"  [red]Before:[/red] {fix.original_code}")
                self.console.print(f"  [green]After:[/green]  {fix.fixed_code}")
            self.console.print()

    def print_full_report(self, result: ScanResult) -> None:
        """Print a complete report: summary, vulnerabilities, and fixes."""
        self.print_summary(result)
        self.console.print()
        self.print_vulnerabilities(result.vulnerabilities)
        self.print_fixes(result.fixes)

    def to_json(self, result: ScanResult) -> str:
        """Serialize scan result to JSON."""
        result.compute_summary()
        return result.model_dump_json(indent=2)

    def save_json(self, result: ScanResult, output_path: str | Path) -> None:
        """Save scan result as a JSON file."""
        output_path = Path(output_path)
        output_path.write_text(self.to_json(result), encoding="utf-8")

    def to_dict(self, result: ScanResult) -> dict:
        """Convert scan result to a dictionary."""
        result.compute_summary()
        return result.model_dump()

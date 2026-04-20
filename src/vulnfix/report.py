"""Report generation for vulnerability scan results."""

from __future__ import annotations

import json
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from vulnfix.models import (
    FindingStatus,
    FindingTriage,
    Fix,
    ScanResult,
    Severity,
    SuppressionRule,
    Vulnerability,
)


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

    def triage_finding(
        self,
        result: ScanResult,
        vulnerability_id: str,
        *,
        status: FindingStatus,
        notes: str | None = None,
        suppression: SuppressionRule | None = None,
        fix_verified: bool = False,
    ) -> FindingTriage:
        """Create or update triage state for a finding."""
        existing = next(
            (entry for entry in result.triage if entry.vulnerability_id == vulnerability_id),
            None,
        )
        if existing is None:
            existing = FindingTriage(vulnerability_id=vulnerability_id)
            result.triage.append(existing)
        existing.status = status
        existing.notes = notes
        existing.suppression = suppression
        existing.fix_verified = fix_verified
        return existing

    def to_sarif(self, result: ScanResult) -> str:
        """Serialize scan results as a SARIF v2.1.0 log."""
        result.compute_summary()
        rules = []
        sarif_results = []
        seen_rules: set[str] = set()

        for vulnerability in result.vulnerabilities:
            rule_id = vulnerability.cwe_id or vulnerability.id
            if rule_id not in seen_rules:
                seen_rules.add(rule_id)
                rules.append(
                    {
                        "id": rule_id,
                        "name": vulnerability.title,
                        "shortDescription": {"text": vulnerability.title},
                        "fullDescription": {"text": vulnerability.description},
                        "properties": {
                            "security-severity": f"{vulnerability.cvss_score:.1f}",
                            "precision": self._confidence_to_precision(vulnerability.confidence),
                            "tags": [
                                vulnerability.owasp_category.value,
                                vulnerability.severity.value,
                            ],
                        },
                    }
                )

            sarif_entry = {
                "ruleId": rule_id,
                "level": self._severity_to_sarif_level(vulnerability.severity),
                "message": {"text": vulnerability.description},
                "properties": {
                    "vulnfixId": vulnerability.id,
                    "confidence": vulnerability.confidence,
                    "remediation": vulnerability.remediation,
                },
            }
            if vulnerability.file_path:
                sarif_entry["locations"] = [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": vulnerability.file_path},
                            "region": {
                                "startLine": vulnerability.line_number or 1,
                            },
                        }
                    }
                ]
            sarif_results.append(sarif_entry)

        sarif_log = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "vulnfix",
                            "version": "0.1.0",
                            "informationUri": "https://github.com/MukundaKatta/vulnfix",
                            "rules": rules,
                        }
                    },
                    "artifacts": [{"location": {"uri": result.target}}],
                    "results": sarif_results,
                }
            ],
        }
        return json.dumps(sarif_log, indent=2)

    @staticmethod
    def _severity_to_sarif_level(severity: Severity) -> str:
        mapping = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "note",
        }
        return mapping[severity]

    @staticmethod
    def _confidence_to_precision(confidence: float) -> str:
        if confidence >= 0.9:
            return "very-high"
        if confidence >= 0.75:
            return "high"
        if confidence >= 0.5:
            return "medium"
        return "low"

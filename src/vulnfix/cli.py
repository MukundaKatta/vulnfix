"""CLI interface for VULNFIX vulnerability scanner."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import click
from rich.console import Console

from vulnfix import __version__
from vulnfix.analyzer.fix import FixSuggester
from vulnfix.analyzer.prioritizer import VulnPrioritizer
from vulnfix.analyzer.severity import CVSSScorer
from vulnfix.models import ScanResult, Vulnerability
from vulnfix.report import ReportGenerator
from vulnfix.scanner.code import CodeScanner
from vulnfix.scanner.config import ConfigScanner
from vulnfix.scanner.dependency import DependencyScanner

console = Console()


def _run_scan(
    scan_type: str,
    target: str,
    code: bool = False,
    deps: bool = False,
    config: bool = False,
) -> ScanResult:
    """Execute scan and return results."""
    vulns: list[Vulnerability] = []

    if code or scan_type == "all":
        console.print("[cyan]Scanning code for vulnerabilities...[/cyan]")
        vulns.extend(CodeScanner().scan(target))

    if deps or scan_type == "all":
        console.print("[cyan]Scanning dependencies for known CVEs...[/cyan]")
        vulns.extend(DependencyScanner().scan(target))

    if config or scan_type == "all":
        console.print("[cyan]Scanning configuration for misconfigurations...[/cyan]")
        vulns.extend(ConfigScanner().scan(target))

    # Score, prioritize, generate fixes
    scorer = CVSSScorer()
    scorer.score_all(vulns)

    prioritizer = VulnPrioritizer()
    vulns = prioritizer.prioritize(vulns)

    suggester = FixSuggester()
    fixes = suggester.suggest_all(vulns)

    result = ScanResult(
        target=target,
        scan_type=scan_type,
        vulnerabilities=vulns,
        fixes=fixes,
        completed_at=datetime.now(),
    )
    result.compute_summary()
    return result


@click.group()
@click.version_option(version=__version__, prog_name="vulnfix")
def cli() -> None:
    """VULNFIX - AI Vulnerability Scanner.

    Detect OWASP Top 10 vulnerabilities, check dependencies against
    known CVEs, and find security misconfigurations.
    """


@cli.group()
def scan() -> None:
    """Run vulnerability scans."""


@scan.command("code")
@click.argument("target", type=click.Path(exists=True))
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table")
@click.option("--output", "-o", type=click.Path(), default=None, help="Save JSON report to file")
def scan_code(target: str, fmt: str, output: str | None) -> None:
    """Scan source code for OWASP Top 10 vulnerabilities."""
    result = _run_scan("code", target, code=True)
    reporter = ReportGenerator(console)

    if fmt == "json" or output:
        if output:
            reporter.save_json(result, output)
            console.print(f"[green]Report saved to {output}[/green]")
        else:
            console.print(reporter.to_json(result))
    else:
        reporter.print_full_report(result)


@scan.command("deps")
@click.argument("target", type=click.Path(exists=True))
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table")
@click.option("--output", "-o", type=click.Path(), default=None)
def scan_deps(target: str, fmt: str, output: str | None) -> None:
    """Check dependencies for known CVEs."""
    result = _run_scan("dependency", target, deps=True)
    reporter = ReportGenerator(console)

    if fmt == "json" or output:
        if output:
            reporter.save_json(result, output)
            console.print(f"[green]Report saved to {output}[/green]")
        else:
            console.print(reporter.to_json(result))
    else:
        reporter.print_full_report(result)


@scan.command("config")
@click.argument("target", type=click.Path(exists=True))
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table")
@click.option("--output", "-o", type=click.Path(), default=None)
def scan_config(target: str, fmt: str, output: str | None) -> None:
    """Scan configuration files for misconfigurations."""
    result = _run_scan("config", target, config=True)
    reporter = ReportGenerator(console)

    if fmt == "json" or output:
        if output:
            reporter.save_json(result, output)
            console.print(f"[green]Report saved to {output}[/green]")
        else:
            console.print(reporter.to_json(result))
    else:
        reporter.print_full_report(result)


@scan.command("all")
@click.argument("target", type=click.Path(exists=True))
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table")
@click.option("--output", "-o", type=click.Path(), default=None)
def scan_all(target: str, fmt: str, output: str | None) -> None:
    """Run all scans (code + dependencies + configuration)."""
    result = _run_scan("all", target)
    reporter = ReportGenerator(console)

    if fmt == "json" or output:
        if output:
            reporter.save_json(result, output)
            console.print(f"[green]Report saved to {output}[/green]")
        else:
            console.print(reporter.to_json(result))
    else:
        reporter.print_full_report(result)


@cli.command()
@click.argument("target", type=click.Path(exists=True))
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table")
@click.option("--output", "-o", type=click.Path(), default=None)
def report(target: str, fmt: str, output: str | None) -> None:
    """Generate a full vulnerability report for a target."""
    result = _run_scan("all", target)
    reporter = ReportGenerator(console)

    if output:
        reporter.save_json(result, output)
        console.print(f"[green]Report saved to {output}[/green]")
    elif fmt == "json":
        console.print(reporter.to_json(result))
    else:
        reporter.print_full_report(result)


if __name__ == "__main__":
    cli()

"""Tests for report generation."""

import json
import tempfile
from pathlib import Path

from rich.console import Console

from vulnfix.models import Fix, OWASPCategory, ScanResult, Severity, Vulnerability
from vulnfix.report import ReportGenerator


class TestReportGenerator:
    def setup_method(self):
        self.console = Console(file=open("/dev/null", "w"), force_terminal=True)
        self.reporter = ReportGenerator(self.console)

    def _make_result(self) -> ScanResult:
        vulns = [
            Vulnerability(
                id="VULNFIX-0001",
                title="SQL Injection",
                description="SQL injection found",
                severity=Severity.CRITICAL,
                owasp_category=OWASPCategory.A03_INJECTION,
                file_path="/app/views.py",
                line_number=10,
                cvss_score=9.8,
                cwe_id="CWE-89",
            ),
            Vulnerability(
                id="VULNFIX-0002",
                title="Debug Mode",
                description="Debug enabled",
                severity=Severity.HIGH,
                owasp_category=OWASPCategory.A05_SECURITY_MISCONFIGURATION,
                file_path="/app/settings.py",
                line_number=5,
                cvss_score=7.0,
            ),
        ]
        fixes = [
            Fix(
                vulnerability_id="VULNFIX-0001",
                title="Use parameterized queries",
                description="Replace string formatting",
                steps=["Step 1"],
            ),
        ]
        return ScanResult(
            target="/app",
            scan_type="code",
            vulnerabilities=vulns,
            fixes=fixes,
        )

    def test_to_json(self):
        result = self._make_result()
        json_str = self.reporter.to_json(result)
        data = json.loads(json_str)
        assert data["target"] == "/app"
        assert len(data["vulnerabilities"]) == 2
        assert data["summary"]["total"] == 2
        assert data["summary"]["critical"] == 1

    def test_save_json(self):
        result = self._make_result()
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            self.reporter.save_json(result, f.name)
            content = Path(f.name).read_text()
        data = json.loads(content)
        assert data["target"] == "/app"

    def test_to_dict(self):
        result = self._make_result()
        d = self.reporter.to_dict(result)
        assert isinstance(d, dict)
        assert d["scan_type"] == "code"

    def test_print_summary(self):
        result = self._make_result()
        # Should not raise
        self.reporter.print_summary(result)

    def test_print_vulnerabilities(self):
        result = self._make_result()
        self.reporter.print_vulnerabilities(result.vulnerabilities)

    def test_print_vulnerabilities_empty(self):
        self.reporter.print_vulnerabilities([])

    def test_print_fixes(self):
        result = self._make_result()
        self.reporter.print_fixes(result.fixes)

    def test_print_full_report(self):
        result = self._make_result()
        self.reporter.print_full_report(result)

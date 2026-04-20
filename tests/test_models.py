"""Tests for data models."""

from vulnfix.models import (
    CVE,
    CVSSMetrics,
    FindingStatus,
    FindingTriage,
    Fix,
    OWASPCategory,
    ScanResult,
    Severity,
    SuppressionRule,
    Vulnerability,
)


class TestVulnerability:
    def test_create_vulnerability(self):
        v = Vulnerability(
            id="VULNFIX-0001",
            title="SQL Injection",
            description="SQL injection found",
            severity=Severity.CRITICAL,
            owasp_category=OWASPCategory.A03_INJECTION,
        )
        assert v.id == "VULNFIX-0001"
        assert v.severity == Severity.CRITICAL
        assert v.cvss_score == 0.0
        assert v.confidence == 0.8

    def test_vulnerability_with_all_fields(self):
        v = Vulnerability(
            id="VULNFIX-0002",
            title="XSS",
            description="Cross-site scripting",
            severity=Severity.HIGH,
            owasp_category=OWASPCategory.A03_INJECTION,
            file_path="/app/views.py",
            line_number=42,
            code_snippet="innerHTML = userInput",
            cvss_score=7.5,
            cwe_id="CWE-79",
            confidence=0.9,
            remediation="Sanitize input",
        )
        assert v.file_path == "/app/views.py"
        assert v.line_number == 42
        assert v.cvss_score == 7.5


class TestCVE:
    def test_create_cve(self):
        cve = CVE(
            cve_id="CVE-2023-12345",
            summary="Test vulnerability",
            severity=Severity.HIGH,
            cvss_score=8.0,
            affected_package="test-pkg",
            affected_versions="<1.0.0",
            fixed_version="1.0.0",
        )
        assert cve.cve_id == "CVE-2023-12345"
        assert cve.fixed_version == "1.0.0"


class TestFix:
    def test_create_fix(self):
        fix = Fix(
            vulnerability_id="VULNFIX-0001",
            title="Use parameterized queries",
            description="Replace string formatting",
            steps=["Step 1", "Step 2"],
        )
        assert fix.vulnerability_id == "VULNFIX-0001"
        assert len(fix.steps) == 2
        assert fix.effort == "medium"
        assert fix.breaking_change is False


class TestScanResult:
    def test_compute_summary(self):
        vulns = [
            Vulnerability(id="1", title="a", description="a", severity=Severity.CRITICAL, owasp_category=OWASPCategory.A03_INJECTION),
            Vulnerability(id="2", title="b", description="b", severity=Severity.CRITICAL, owasp_category=OWASPCategory.A03_INJECTION),
            Vulnerability(id="3", title="c", description="c", severity=Severity.HIGH, owasp_category=OWASPCategory.A03_INJECTION),
            Vulnerability(id="4", title="d", description="d", severity=Severity.MEDIUM, owasp_category=OWASPCategory.A05_SECURITY_MISCONFIGURATION),
            Vulnerability(id="5", title="e", description="e", severity=Severity.LOW, owasp_category=OWASPCategory.A09_LOGGING_FAILURES),
        ]
        result = ScanResult(target="/app", scan_type="code", vulnerabilities=vulns)
        summary = result.compute_summary()
        assert summary["critical"] == 2
        assert summary["high"] == 1
        assert summary["medium"] == 1
        assert summary["low"] == 1
        assert summary["total"] == 5

    def test_build_default_triage(self):
        result = ScanResult(
            target="/app",
            scan_type="code",
            vulnerabilities=[
                Vulnerability(
                    id="1",
                    title="a",
                    description="a",
                    severity=Severity.CRITICAL,
                    owasp_category=OWASPCategory.A03_INJECTION,
                )
            ],
        )
        triage = result.build_default_triage()
        assert len(triage) == 1
        assert triage[0].status == FindingStatus.NEW


class TestCVSSMetrics:
    def test_defaults(self):
        m = CVSSMetrics()
        assert m.attack_vector.value == "NETWORK"
        assert m.attack_complexity.value == "LOW"


class TestTriageModels:
    def test_suppression_rule(self):
        rule = SuppressionRule(file_path="app.py", reason="accepted false positive")
        assert rule.reason == "accepted false positive"

    def test_finding_triage(self):
        triage = FindingTriage(vulnerability_id="VULNFIX-1", status=FindingStatus.TRIAGED)
        assert triage.status == FindingStatus.TRIAGED

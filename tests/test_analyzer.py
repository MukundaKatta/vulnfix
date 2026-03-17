"""Tests for analyzer modules."""

from vulnfix.analyzer.fix import FixSuggester
from vulnfix.analyzer.prioritizer import VulnPrioritizer
from vulnfix.analyzer.severity import CVSSScorer
from vulnfix.models import (
    AttackComplexity,
    AttackVector,
    CVSSMetrics,
    OWASPCategory,
    Severity,
    Vulnerability,
)


class TestCVSSScorer:
    def setup_method(self):
        self.scorer = CVSSScorer()

    def test_score_network_low_complexity(self):
        metrics = CVSSMetrics(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required="NONE",
            user_interaction="NONE",
            scope="UNCHANGED",
            confidentiality_impact="HIGH",
            integrity_impact="HIGH",
            availability_impact="HIGH",
        )
        score = self.scorer.score(metrics)
        assert 9.0 <= score <= 10.0  # Should be critical

    def test_score_local_high_complexity(self):
        metrics = CVSSMetrics(
            attack_vector=AttackVector.LOCAL,
            attack_complexity=AttackComplexity.HIGH,
            privileges_required="HIGH",
            user_interaction="REQUIRED",
            scope="UNCHANGED",
            confidentiality_impact="LOW",
            integrity_impact="NONE",
            availability_impact="NONE",
        )
        score = self.scorer.score(metrics)
        assert 0.0 < score < 4.0  # Should be low

    def test_score_zero_impact(self):
        metrics = CVSSMetrics(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            confidentiality_impact="NONE",
            integrity_impact="NONE",
            availability_impact="NONE",
        )
        score = self.scorer.score(metrics)
        assert score == 0.0

    def test_score_changed_scope(self):
        metrics = CVSSMetrics(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required="NONE",
            user_interaction="NONE",
            scope="CHANGED",
            confidentiality_impact="HIGH",
            integrity_impact="HIGH",
            availability_impact="HIGH",
        )
        score = self.scorer.score(metrics)
        assert score == 10.0

    def test_score_vulnerability_with_metrics(self):
        vuln = Vulnerability(
            id="test",
            title="Test",
            description="Test",
            severity=Severity.HIGH,
            owasp_category=OWASPCategory.A03_INJECTION,
            cvss_metrics=CVSSMetrics(
                attack_vector=AttackVector.NETWORK,
                attack_complexity=AttackComplexity.LOW,
                confidentiality_impact="HIGH",
                integrity_impact="HIGH",
                availability_impact="NONE",
            ),
        )
        score = self.scorer.score_vulnerability(vuln)
        assert score > 0
        assert vuln.cvss_score == score

    def test_score_vulnerability_fallback(self):
        vuln = Vulnerability(
            id="test",
            title="Test",
            description="Test",
            severity=Severity.CRITICAL,
            owasp_category=OWASPCategory.A03_INJECTION,
        )
        score = self.scorer.score_vulnerability(vuln)
        assert score == 9.5

    def test_severity_from_score(self):
        assert CVSSScorer.severity_from_score(9.5) == Severity.CRITICAL
        assert CVSSScorer.severity_from_score(7.5) == Severity.HIGH
        assert CVSSScorer.severity_from_score(5.0) == Severity.MEDIUM
        assert CVSSScorer.severity_from_score(2.0) == Severity.LOW
        assert CVSSScorer.severity_from_score(0.0) == Severity.INFO

    def test_score_all(self):
        vulns = [
            Vulnerability(id="1", title="a", description="a", severity=Severity.HIGH, owasp_category=OWASPCategory.A03_INJECTION),
            Vulnerability(id="2", title="b", description="b", severity=Severity.LOW, owasp_category=OWASPCategory.A05_SECURITY_MISCONFIGURATION),
        ]
        scored = self.scorer.score_all(vulns)
        assert scored[0].cvss_score == 7.5
        assert scored[1].cvss_score == 2.5


class TestFixSuggester:
    def setup_method(self):
        self.suggester = FixSuggester()

    def test_suggest_known_pattern(self):
        vuln = Vulnerability(
            id="VULNFIX-0001",
            title="Sql Injection Fstring",
            description="SQL injection via f-string",
            severity=Severity.CRITICAL,
            owasp_category=OWASPCategory.A03_INJECTION,
            cwe_id="CWE-89",
        )
        fix = self.suggester.suggest(vuln)
        assert fix.vulnerability_id == "VULNFIX-0001"
        assert "parameterized" in fix.title.lower() or "f-string" in fix.title.lower()
        assert fix.original_code is not None
        assert fix.fixed_code is not None
        assert len(fix.steps) > 0

    def test_suggest_unknown_pattern(self):
        vuln = Vulnerability(
            id="VULNFIX-9999",
            title="Some Unknown Vuln",
            description="Unknown vulnerability type",
            severity=Severity.MEDIUM,
            owasp_category=OWASPCategory.A03_INJECTION,
            remediation="Apply the fix",
        )
        fix = self.suggester.suggest(vuln)
        assert fix.vulnerability_id == "VULNFIX-9999"
        assert fix.title is not None

    def test_suggest_all(self):
        vulns = [
            Vulnerability(id="1", title="Pickle Load", description="d", severity=Severity.CRITICAL, owasp_category=OWASPCategory.A08_DATA_INTEGRITY_FAILURES),
            Vulnerability(id="2", title="Debug Mode Enabled", description="d", severity=Severity.HIGH, owasp_category=OWASPCategory.A05_SECURITY_MISCONFIGURATION),
        ]
        fixes = self.suggester.suggest_all(vulns)
        assert len(fixes) == 2


class TestVulnPrioritizer:
    def setup_method(self):
        self.prioritizer = VulnPrioritizer()

    def test_prioritize_ordering(self):
        critical = Vulnerability(
            id="1", title="SQLi", description="d", severity=Severity.CRITICAL,
            owasp_category=OWASPCategory.A03_INJECTION, cwe_id="CWE-89", cvss_score=9.8,
        )
        low = Vulnerability(
            id="2", title="Info", description="d", severity=Severity.LOW,
            owasp_category=OWASPCategory.A09_LOGGING_FAILURES, cwe_id="CWE-532", cvss_score=2.0,
        )
        result = self.prioritizer.prioritize([low, critical])
        assert result[0].id == "1"  # Critical should come first
        assert result[1].id == "2"

    def test_priority_score_range(self):
        vuln = Vulnerability(
            id="1", title="a", description="d", severity=Severity.MEDIUM,
            owasp_category=OWASPCategory.A03_INJECTION, cwe_id="CWE-89",
        )
        score = self.prioritizer.priority_score(vuln)
        assert 0.0 <= score <= 100.0

    def test_prioritize_with_scores(self):
        vulns = [
            Vulnerability(id="1", title="a", description="d", severity=Severity.HIGH, owasp_category=OWASPCategory.A03_INJECTION, cwe_id="CWE-89", cvss_score=8.0),
            Vulnerability(id="2", title="b", description="d", severity=Severity.LOW, owasp_category=OWASPCategory.A09_LOGGING_FAILURES, cwe_id="CWE-532", cvss_score=2.0),
        ]
        scored = self.prioritizer.prioritize_with_scores(vulns)
        assert len(scored) == 2
        assert scored[0][1] > scored[1][1]  # First has higher score

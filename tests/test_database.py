"""Tests for database modules."""

from vulnfix.database.cves import CVEDatabase
from vulnfix.database.patterns import VulnerabilityPatterns
from vulnfix.models import OWASPCategory


class TestCVEDatabase:
    def setup_method(self):
        self.db = CVEDatabase()

    def test_has_50_plus_cves(self):
        assert len(self.db.cves) >= 50

    def test_lookup_django(self):
        results = self.db.lookup("django")
        assert len(results) >= 1
        assert all("django" in c.affected_package.lower() for c in results)

    def test_lookup_with_version(self):
        results = self.db.lookup("django", "4.0.0")
        assert len(results) >= 1

    def test_lookup_nonexistent(self):
        results = self.db.lookup("nonexistent-package-xyz")
        assert results == []

    def test_search_by_cve_id(self):
        results = self.db.search("CVE-2023-36053")
        assert len(results) == 1
        assert results[0].cve_id == "CVE-2023-36053"

    def test_search_by_keyword(self):
        results = self.db.search("injection")
        assert len(results) >= 1

    def test_all_cves_have_required_fields(self):
        for cve in self.db.cves:
            assert cve.cve_id.startswith("CVE-")
            assert cve.summary
            assert cve.affected_package
            assert 0.0 <= cve.cvss_score <= 10.0


class TestVulnerabilityPatterns:
    def setup_method(self):
        self.patterns = VulnerabilityPatterns()

    def test_has_patterns(self):
        assert len(self.patterns.patterns) >= 20

    def test_get_by_category_injection(self):
        injection_patterns = self.patterns.get_by_category(OWASPCategory.A03_INJECTION)
        assert len(injection_patterns) >= 4  # SQL injection + XSS patterns

    def test_get_by_category_auth(self):
        auth_patterns = self.patterns.get_by_category(OWASPCategory.A07_AUTH_FAILURES)
        assert len(auth_patterns) >= 3

    def test_all_patterns_have_required_fields(self):
        for p in self.patterns.patterns:
            assert p.name
            assert p.pattern is not None
            assert p.severity is not None
            assert p.owasp_category is not None
            assert p.cwe_id
            assert p.description
            assert p.remediation

    def test_sql_injection_pattern_matches(self):
        import re
        injection_patterns = self.patterns.get_by_category(OWASPCategory.A03_INJECTION)
        sql_patterns = [p for p in injection_patterns if "sql" in p.name]
        test_code = 'cursor.execute(f"SELECT * FROM users WHERE id = {uid}")'
        matched = any(p.pattern.search(test_code) for p in sql_patterns)
        assert matched

    def test_xss_pattern_matches(self):
        xss_patterns = [p for p in self.patterns.patterns if "xss" in p.name]
        test_code = "element.innerHTML = userInput;"
        matched = any(p.pattern.search(test_code) for p in xss_patterns)
        assert matched

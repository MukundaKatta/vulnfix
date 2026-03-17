"""Vulnerability prioritizer that ranks findings by exploitability and impact."""

from __future__ import annotations

from vulnfix.models import Severity, Vulnerability


class VulnPrioritizer:
    """Ranks vulnerabilities by a composite score based on exploitability, impact, and confidence."""

    # Exploitability weights by CWE category
    _EXPLOITABILITY: dict[str, float] = {
        "CWE-89": 1.0,    # SQL injection - trivially exploitable
        "CWE-79": 0.9,    # XSS
        "CWE-78": 1.0,    # OS command injection
        "CWE-95": 1.0,    # eval injection
        "CWE-502": 0.9,   # deserialization
        "CWE-798": 0.8,   # hardcoded credentials
        "CWE-22": 0.8,    # path traversal
        "CWE-918": 0.8,   # SSRF
        "CWE-352": 0.7,   # CSRF
        "CWE-327": 0.6,   # weak crypto
        "CWE-328": 0.6,   # weak hash
        "CWE-330": 0.5,   # insecure random
        "CWE-295": 0.7,   # improper cert validation
        "CWE-345": 0.9,   # insufficient verification
        "CWE-521": 0.9,   # weak passwords
        "CWE-489": 0.5,   # debug mode
        "CWE-532": 0.4,   # info exposure through log
        "CWE-668": 0.6,   # exposed resource
        "CWE-915": 0.7,   # mass assignment
        "CWE-942": 0.5,   # CORS misconfiguration
        "CWE-16": 0.4,    # configuration
        "CWE-209": 0.4,   # error info exposure
        "CWE-311": 0.6,   # missing encryption
    }

    _SEVERITY_WEIGHT: dict[Severity, float] = {
        Severity.CRITICAL: 1.0,
        Severity.HIGH: 0.8,
        Severity.MEDIUM: 0.5,
        Severity.LOW: 0.2,
        Severity.INFO: 0.05,
    }

    def priority_score(self, vuln: Vulnerability) -> float:
        """Compute a composite priority score (0-100) for a vulnerability."""
        # Components
        severity_w = self._SEVERITY_WEIGHT.get(vuln.severity, 0.5)
        exploitability = self._EXPLOITABILITY.get(vuln.cwe_id or "", 0.5)
        cvss_norm = vuln.cvss_score / 10.0
        confidence = vuln.confidence

        # Weighted composite
        score = (
            severity_w * 30
            + exploitability * 30
            + cvss_norm * 25
            + confidence * 15
        )
        return round(min(score, 100.0), 1)

    def prioritize(self, vulns: list[Vulnerability]) -> list[Vulnerability]:
        """Sort vulnerabilities by priority (highest first)."""
        return sorted(vulns, key=lambda v: self.priority_score(v), reverse=True)

    def prioritize_with_scores(
        self, vulns: list[Vulnerability]
    ) -> list[tuple[Vulnerability, float]]:
        """Return vulnerabilities paired with their priority scores, sorted highest first."""
        scored = [(v, self.priority_score(v)) for v in vulns]
        scored.sort(key=lambda x: x[1], reverse=True)
        return scored

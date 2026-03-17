"""CVSS v3.1 scorer for computing vulnerability severity scores."""

from __future__ import annotations

import math

from vulnfix.models import AttackComplexity, AttackVector, CVSSMetrics, Severity, Vulnerability


class CVSSScorer:
    """Computes CVSS v3.1 base scores following the official specification."""

    # Weight tables per CVSS v3.1 specification
    _AV_WEIGHTS = {
        AttackVector.NETWORK: 0.85,
        AttackVector.ADJACENT: 0.62,
        AttackVector.LOCAL: 0.55,
        AttackVector.PHYSICAL: 0.20,
    }

    _AC_WEIGHTS = {
        AttackComplexity.LOW: 0.77,
        AttackComplexity.HIGH: 0.44,
    }

    _PR_WEIGHTS_UNCHANGED = {"NONE": 0.85, "LOW": 0.62, "HIGH": 0.27}
    _PR_WEIGHTS_CHANGED = {"NONE": 0.85, "LOW": 0.68, "HIGH": 0.50}

    _UI_WEIGHTS = {"NONE": 0.85, "REQUIRED": 0.62}

    _IMPACT_WEIGHTS = {"NONE": 0.0, "LOW": 0.22, "HIGH": 0.56}

    def score(self, metrics: CVSSMetrics) -> float:
        """Compute the CVSS v3.1 base score from metrics."""
        # Exploitability sub-score
        av = self._AV_WEIGHTS.get(metrics.attack_vector, 0.85)
        ac = self._AC_WEIGHTS.get(metrics.attack_complexity, 0.77)

        pr_table = (
            self._PR_WEIGHTS_CHANGED if metrics.scope == "CHANGED" else self._PR_WEIGHTS_UNCHANGED
        )
        pr = pr_table.get(metrics.privileges_required, 0.85)
        ui = self._UI_WEIGHTS.get(metrics.user_interaction, 0.85)

        exploitability = 8.22 * av * ac * pr * ui

        # Impact sub-score
        c = self._IMPACT_WEIGHTS.get(metrics.confidentiality_impact, 0.0)
        i = self._IMPACT_WEIGHTS.get(metrics.integrity_impact, 0.0)
        a = self._IMPACT_WEIGHTS.get(metrics.availability_impact, 0.0)

        isc_base = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))

        if metrics.scope == "CHANGED":
            impact = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15
        else:
            impact = 6.42 * isc_base

        if impact <= 0:
            return 0.0

        if metrics.scope == "CHANGED":
            base_score = min(1.08 * (impact + exploitability), 10.0)
        else:
            base_score = min(impact + exploitability, 10.0)

        # Round up to one decimal
        return math.ceil(base_score * 10) / 10

    def score_vulnerability(self, vuln: Vulnerability) -> float:
        """Score a vulnerability. If it has CVSS metrics, compute; otherwise estimate from severity."""
        if vuln.cvss_metrics:
            computed = self.score(vuln.cvss_metrics)
            vuln.cvss_score = computed
            return computed

        # Fallback: estimate from severity level
        estimates = {
            Severity.CRITICAL: 9.5,
            Severity.HIGH: 7.5,
            Severity.MEDIUM: 5.0,
            Severity.LOW: 2.5,
            Severity.INFO: 0.0,
        }
        estimated = estimates.get(vuln.severity, 5.0)
        vuln.cvss_score = estimated
        return estimated

    @staticmethod
    def severity_from_score(score: float) -> Severity:
        """Map a CVSS score to a severity level."""
        if score >= 9.0:
            return Severity.CRITICAL
        elif score >= 7.0:
            return Severity.HIGH
        elif score >= 4.0:
            return Severity.MEDIUM
        elif score > 0.0:
            return Severity.LOW
        return Severity.INFO

    def score_all(self, vulns: list[Vulnerability]) -> list[Vulnerability]:
        """Score all vulnerabilities in a list."""
        for v in vulns:
            self.score_vulnerability(v)
        return vulns

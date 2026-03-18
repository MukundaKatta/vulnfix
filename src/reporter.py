"""Security report generation."""
import json, time
from typing import Dict, List
from dataclasses import dataclass

@dataclass
class SecurityReport:
    title: str
    scan_results: List[Dict]
    overall_risk: str
    summary: str
    recommendations: List[str]
    generated_at: float

class ReportGenerator:
    """Generate structured security reports."""

    RISK_LEVELS = [(80, "CRITICAL"), (60, "HIGH"), (40, "MEDIUM"), (20, "LOW"), (0, "MINIMAL")]

    def generate(self, scan_results: List[Dict], title: str = "Security Scan Report") -> SecurityReport:
        max_risk = max((r.get("risk_score", 0) for r in scan_results), default=0)
        risk_label = next(label for threshold, label in self.RISK_LEVELS if max_risk >= threshold)

        total_findings = sum(r.get("threats_found", 0) for r in scan_results)
        critical = sum(1 for r in scan_results for f in r.get("findings", []) if f.get("level") == "critical")
        high = sum(1 for r in scan_results for f in r.get("findings", []) if f.get("level") == "high")

        summary = f"Scanned {len(scan_results)} targets. Found {total_findings} issues ({critical} critical, {high} high)."

        recommendations = []
        if critical > 0:
            recommendations.append("URGENT: Address all critical vulnerabilities immediately")
        if high > 0:
            recommendations.append("Schedule remediation for high-severity findings within 48 hours")
        recommendations.append("Run follow-up scan after fixes are applied")
        recommendations.append("Review access controls and input validation")

        return SecurityReport(title=title, scan_results=scan_results, overall_risk=risk_label,
                            summary=summary, recommendations=recommendations, generated_at=time.time())

    def to_json(self, report: SecurityReport) -> str:
        return json.dumps({"title": report.title, "overall_risk": report.overall_risk,
                          "summary": report.summary, "recommendations": report.recommendations,
                          "findings_count": len(report.scan_results),
                          "generated_at": report.generated_at}, indent=2)

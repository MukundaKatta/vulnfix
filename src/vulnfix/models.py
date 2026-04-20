"""Data models for VULNFIX vulnerability scanner."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str, Enum):
    NEW = "new"
    TRIAGED = "triaged"
    SUPPRESSED = "suppressed"
    FIXED = "fixed"
    NEEDS_VERIFICATION = "needs_verification"


class OWASPCategory(str, Enum):
    A01_BROKEN_ACCESS_CONTROL = "A01:2021 - Broken Access Control"
    A02_CRYPTOGRAPHIC_FAILURES = "A02:2021 - Cryptographic Failures"
    A03_INJECTION = "A03:2021 - Injection"
    A04_INSECURE_DESIGN = "A04:2021 - Insecure Design"
    A05_SECURITY_MISCONFIGURATION = "A05:2021 - Security Misconfiguration"
    A06_VULNERABLE_COMPONENTS = "A06:2021 - Vulnerable and Outdated Components"
    A07_AUTH_FAILURES = "A07:2021 - Identification and Authentication Failures"
    A08_DATA_INTEGRITY_FAILURES = "A08:2021 - Software and Data Integrity Failures"
    A09_LOGGING_FAILURES = "A09:2021 - Security Logging and Monitoring Failures"
    A10_SSRF = "A10:2021 - Server-Side Request Forgery"


class AttackVector(str, Enum):
    NETWORK = "NETWORK"
    ADJACENT = "ADJACENT_NETWORK"
    LOCAL = "LOCAL"
    PHYSICAL = "PHYSICAL"


class AttackComplexity(str, Enum):
    LOW = "LOW"
    HIGH = "HIGH"


class CVSSMetrics(BaseModel):
    """CVSS v3.1 base metrics."""

    attack_vector: AttackVector = AttackVector.NETWORK
    attack_complexity: AttackComplexity = AttackComplexity.LOW
    privileges_required: str = "NONE"
    user_interaction: str = "NONE"
    scope: str = "UNCHANGED"
    confidentiality_impact: str = "HIGH"
    integrity_impact: str = "HIGH"
    availability_impact: str = "NONE"


class Vulnerability(BaseModel):
    """A detected vulnerability."""

    id: str = Field(description="Unique identifier for this finding")
    title: str
    description: str
    severity: Severity
    owasp_category: OWASPCategory
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    cvss_score: float = Field(ge=0.0, le=10.0, default=0.0)
    cvss_metrics: Optional[CVSSMetrics] = None
    cwe_id: Optional[str] = None
    confidence: float = Field(ge=0.0, le=1.0, default=0.8)
    remediation: Optional[str] = None


class CVE(BaseModel):
    """A known CVE entry."""

    cve_id: str = Field(description="CVE identifier, e.g. CVE-2021-44228")
    summary: str
    severity: Severity
    cvss_score: float = Field(ge=0.0, le=10.0)
    affected_package: str
    affected_versions: str
    fixed_version: Optional[str] = None
    published_date: Optional[str] = None
    references: list[str] = Field(default_factory=list)


class Fix(BaseModel):
    """A suggested fix for a vulnerability."""

    vulnerability_id: str
    title: str
    description: str
    original_code: Optional[str] = None
    fixed_code: Optional[str] = None
    steps: list[str] = Field(default_factory=list)
    effort: str = "medium"  # low, medium, high
    breaking_change: bool = False


class SuppressionRule(BaseModel):
    """Structured suppression rule for accepted findings."""

    vulnerability_id: Optional[str] = None
    file_path: Optional[str] = None
    reason: str
    expires_at: Optional[str] = None


class FindingTriage(BaseModel):
    """Workflow state for one vulnerability finding."""

    vulnerability_id: str
    status: FindingStatus = FindingStatus.NEW
    notes: Optional[str] = None
    suppression: Optional[SuppressionRule] = None
    fix_verified: bool = False


class ScanResult(BaseModel):
    """Result of a complete scan."""

    scan_id: str = Field(default_factory=lambda: f"scan-{datetime.now().strftime('%Y%m%d-%H%M%S')}")
    target: str
    scan_type: str  # code, dependency, config, all
    started_at: datetime = Field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    fixes: list[Fix] = Field(default_factory=list)
    triage: list[FindingTriage] = Field(default_factory=list)
    summary: dict[str, int] = Field(default_factory=dict)

    def compute_summary(self) -> dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}
        for v in self.vulnerabilities:
            counts[v.severity.value] += 1
            counts["total"] += 1
        self.summary = counts
        return counts

    def build_default_triage(self) -> list[FindingTriage]:
        """Create default triage entries for all findings."""
        self.triage = [
            FindingTriage(vulnerability_id=vulnerability.id)
            for vulnerability in self.vulnerabilities
        ]
        return self.triage

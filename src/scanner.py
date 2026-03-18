"""Threat scanning engine."""
import re, hashlib, logging, time
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)

class ThreatLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class ThreatSignature:
    id: str
    name: str
    pattern: str
    level: ThreatLevel
    description: str
    cve_id: Optional[str] = None

@dataclass
class ScanResult:
    target: str
    threats_found: int
    findings: List[Dict]
    scan_duration_ms: float
    risk_score: float  # 0-100
    timestamp: float = field(default_factory=time.time)

class ThreatScanner:
    """Multi-pattern threat detection engine."""

    SIGNATURES = [
        ThreatSignature("SIG-001", "SQL Injection", r"(?:UNION\s+SELECT|OR\s+1=1|DROP\s+TABLE|;\s*DELETE)", ThreatLevel.CRITICAL, "SQL injection attempt"),
        ThreatSignature("SIG-002", "XSS Attack", r"<script[^>]*>|javascript:|on\w+\s*=", ThreatLevel.HIGH, "Cross-site scripting"),
        ThreatSignature("SIG-003", "Path Traversal", r"\.\./|\.\.\\|%2e%2e", ThreatLevel.HIGH, "Directory traversal attempt"),
        ThreatSignature("SIG-004", "Command Injection", r";\s*(?:cat|ls|rm|wget|curl)\s|\|\s*(?:bash|sh|cmd)", ThreatLevel.CRITICAL, "OS command injection"),
        ThreatSignature("SIG-005", "SSRF", r"(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|169\.254)", ThreatLevel.HIGH, "Server-side request forgery"),
        ThreatSignature("SIG-006", "Sensitive Data", r"(?:password|secret|api[_-]?key|token|credential)\s*[=:]", ThreatLevel.MEDIUM, "Potential sensitive data exposure"),
        ThreatSignature("SIG-007", "Email Harvest", r"[\w.-]+@[\w.-]+\.\w{2,}", ThreatLevel.LOW, "Email address detected"),
        ThreatSignature("SIG-008", "Base64 Payload", r"(?:[A-Za-z0-9+/]{40,}={0,2})", ThreatLevel.MEDIUM, "Encoded payload detected"),
    ]

    def __init__(self, custom_signatures: List[ThreatSignature] = None):
        self.signatures = self.SIGNATURES + (custom_signatures or [])
        self._compiled = [(sig, re.compile(sig.pattern, re.IGNORECASE)) for sig in self.signatures]
        self._scan_count = 0
        self._total_threats = 0

    def scan(self, content: str, target: str = "input") -> ScanResult:
        start = time.time()
        self._scan_count += 1
        findings = []

        for sig, pattern in self._compiled:
            matches = pattern.findall(content)
            if matches:
                findings.append({
                    "signature_id": sig.id,
                    "name": sig.name,
                    "level": sig.level.value,
                    "description": sig.description,
                    "matches": len(matches),
                    "sample": matches[0][:100] if matches else "",
                    "cve_id": sig.cve_id,
                })

        self._total_threats += len(findings)

        # Calculate risk score (0-100)
        level_scores = {"critical": 40, "high": 25, "medium": 15, "low": 5, "info": 1}
        risk = min(100, sum(level_scores.get(f["level"], 0) for f in findings))

        elapsed = (time.time() - start) * 1000
        return ScanResult(target=target, threats_found=len(findings), findings=findings,
                         scan_duration_ms=round(elapsed, 2), risk_score=risk)

    def scan_batch(self, items: List[Tuple[str, str]]) -> List[ScanResult]:
        return [self.scan(content, target) for target, content in items]

    @property
    def stats(self) -> Dict:
        return {"scans": self._scan_count, "total_threats": self._total_threats,
                "signatures_loaded": len(self.signatures)}

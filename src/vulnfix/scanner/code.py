"""Code scanner for detecting OWASP Top 10 vulnerabilities using regex patterns."""

from __future__ import annotations

import os
from pathlib import Path

from vulnfix.database.patterns import VulnerabilityPatterns
from vulnfix.models import Vulnerability


class CodeScanner:
    """Scans source code files for OWASP Top 10 vulnerability patterns."""

    SUPPORTED_EXTENSIONS = {
        ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".rb", ".php",
        ".go", ".rs", ".html", ".htm", ".jinja", ".jinja2", ".sql",
        ".yml", ".yaml", ".json", ".toml", ".ini", ".cfg", ".conf",
    }

    def __init__(self) -> None:
        self._patterns = VulnerabilityPatterns()
        self._counter = 0

    def scan_file(self, file_path: str | Path) -> list[Vulnerability]:
        """Scan a single file for vulnerability patterns."""
        file_path = Path(file_path)
        if not file_path.is_file():
            return []
        if file_path.suffix.lower() not in self.SUPPORTED_EXTENSIONS:
            return []

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except (OSError, PermissionError):
            return []

        vulnerabilities: list[Vulnerability] = []
        lines = content.splitlines()

        for pattern in self._patterns.patterns:
            for line_num, line in enumerate(lines, start=1):
                match = pattern.pattern.search(line)
                if match:
                    self._counter += 1
                    vuln = Vulnerability(
                        id=f"VULNFIX-{self._counter:04d}",
                        title=pattern.name.replace("_", " ").title(),
                        description=pattern.description,
                        severity=pattern.severity,
                        owasp_category=pattern.owasp_category,
                        file_path=str(file_path),
                        line_number=line_num,
                        code_snippet=line.strip(),
                        cwe_id=pattern.cwe_id,
                        confidence=pattern.confidence,
                        remediation=pattern.remediation,
                    )
                    vulnerabilities.append(vuln)

        return vulnerabilities

    def scan_directory(self, directory: str | Path) -> list[Vulnerability]:
        """Recursively scan a directory for vulnerability patterns."""
        directory = Path(directory)
        if not directory.is_dir():
            return []

        vulnerabilities: list[Vulnerability] = []
        for root, dirs, files in os.walk(directory):
            # Skip hidden and common non-source directories
            dirs[:] = [
                d for d in dirs
                if not d.startswith(".")
                and d not in {"node_modules", "__pycache__", "venv", ".venv", "env", "dist", "build", ".git"}
            ]
            for filename in files:
                file_path = Path(root) / filename
                vulnerabilities.extend(self.scan_file(file_path))

        return vulnerabilities

    def scan(self, target: str | Path) -> list[Vulnerability]:
        """Scan a file or directory."""
        target = Path(target)
        if target.is_file():
            return self.scan_file(target)
        elif target.is_dir():
            return self.scan_directory(target)
        return []

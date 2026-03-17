"""Dependency scanner that checks packages against known CVEs."""

from __future__ import annotations

import re
from pathlib import Path

from vulnfix.database.cves import CVEDatabase
from vulnfix.models import OWASPCategory, Vulnerability


class DependencyScanner:
    """Scans dependency files (requirements.txt, etc.) for known vulnerable packages."""

    def __init__(self) -> None:
        self._cve_db = CVEDatabase()
        self._counter = 0

    def scan(self, target: str | Path) -> list[Vulnerability]:
        """Scan a requirements file or directory for vulnerable dependencies."""
        target = Path(target)
        if target.is_file():
            return self._scan_requirements_file(target)
        elif target.is_dir():
            vulns: list[Vulnerability] = []
            for req_file in target.rglob("requirements*.txt"):
                vulns.extend(self._scan_requirements_file(req_file))
            setup_cfg = target / "setup.cfg"
            if setup_cfg.exists():
                vulns.extend(self._scan_setup_cfg(setup_cfg))
            pyproject = target / "pyproject.toml"
            if pyproject.exists():
                vulns.extend(self._scan_pyproject(pyproject))
            return vulns
        return []

    def _scan_requirements_file(self, file_path: Path) -> list[Vulnerability]:
        """Parse requirements.txt and check each package."""
        if not file_path.is_file():
            return []

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except (OSError, PermissionError):
            return []

        vulnerabilities: list[Vulnerability] = []
        for line_num, line in enumerate(content.splitlines(), start=1):
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue

            pkg, version = self._parse_requirement(line)
            if not pkg:
                continue

            cves = self._cve_db.lookup(pkg, version)
            for cve in cves:
                self._counter += 1
                fix_hint = f"Upgrade {pkg} to {cve.fixed_version}" if cve.fixed_version else f"Check {cve.cve_id} for remediation."
                vuln = Vulnerability(
                    id=f"VULNFIX-DEP-{self._counter:04d}",
                    title=f"{cve.cve_id} in {pkg}",
                    description=cve.summary,
                    severity=cve.severity,
                    owasp_category=OWASPCategory.A06_VULNERABLE_COMPONENTS,
                    file_path=str(file_path),
                    line_number=line_num,
                    code_snippet=line,
                    cvss_score=cve.cvss_score,
                    cwe_id=None,
                    confidence=0.95,
                    remediation=fix_hint,
                )
                vulnerabilities.append(vuln)

        return vulnerabilities

    def _scan_setup_cfg(self, file_path: Path) -> list[Vulnerability]:
        """Basic scan of setup.cfg install_requires."""
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except (OSError, PermissionError):
            return []

        vulns: list[Vulnerability] = []
        in_deps = False
        for line_num, line in enumerate(content.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("install_requires"):
                in_deps = True
                continue
            if in_deps:
                if stripped and not stripped.startswith("[") and not stripped.startswith("#"):
                    pkg, version = self._parse_requirement(stripped)
                    if pkg:
                        for cve in self._cve_db.lookup(pkg, version):
                            self._counter += 1
                            vulns.append(Vulnerability(
                                id=f"VULNFIX-DEP-{self._counter:04d}",
                                title=f"{cve.cve_id} in {pkg}",
                                description=cve.summary,
                                severity=cve.severity,
                                owasp_category=OWASPCategory.A06_VULNERABLE_COMPONENTS,
                                file_path=str(file_path),
                                line_number=line_num,
                                code_snippet=stripped,
                                cvss_score=cve.cvss_score,
                                confidence=0.9,
                                remediation=f"Upgrade {pkg} to {cve.fixed_version}" if cve.fixed_version else f"Check {cve.cve_id}.",
                            ))
                elif stripped.startswith("["):
                    in_deps = False
        return vulns

    def _scan_pyproject(self, file_path: Path) -> list[Vulnerability]:
        """Basic scan of pyproject.toml dependencies."""
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except (OSError, PermissionError):
            return []

        vulns: list[Vulnerability] = []
        for line_num, line in enumerate(content.splitlines(), start=1):
            stripped = line.strip().strip('"').strip("'").strip(",")
            if not stripped or stripped.startswith("#") or stripped.startswith("["):
                continue
            pkg, version = self._parse_requirement(stripped)
            if pkg:
                for cve in self._cve_db.lookup(pkg, version):
                    self._counter += 1
                    vulns.append(Vulnerability(
                        id=f"VULNFIX-DEP-{self._counter:04d}",
                        title=f"{cve.cve_id} in {pkg}",
                        description=cve.summary,
                        severity=cve.severity,
                        owasp_category=OWASPCategory.A06_VULNERABLE_COMPONENTS,
                        file_path=str(file_path),
                        line_number=line_num,
                        code_snippet=stripped,
                        cvss_score=cve.cvss_score,
                        confidence=0.9,
                        remediation=f"Upgrade {pkg} to {cve.fixed_version}" if cve.fixed_version else f"Check {cve.cve_id}.",
                    ))
        return vulns

    @staticmethod
    def _parse_requirement(line: str) -> tuple[str | None, str | None]:
        """Parse a requirement line into (package_name, version)."""
        line = line.split("#")[0].strip()
        if not line:
            return None, None

        match = re.match(r'^([a-zA-Z0-9_.-]+)\s*(?:[>=<!~]+\s*([0-9][0-9a-zA-Z.*]*))?', line)
        if match:
            pkg = match.group(1).lower().replace("_", "-")
            ver = match.group(2)
            return pkg, ver
        return None, None

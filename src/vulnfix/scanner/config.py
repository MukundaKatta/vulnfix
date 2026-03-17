"""Configuration scanner for finding security misconfigurations."""

from __future__ import annotations

import os
import re
from pathlib import Path

from vulnfix.models import OWASPCategory, Severity, Vulnerability


class _ConfigPattern:
    """A configuration misconfiguration pattern."""

    def __init__(
        self,
        name: str,
        pattern: re.Pattern,
        severity: Severity,
        description: str,
        remediation: str,
        cwe_id: str = "CWE-16",
        confidence: float = 0.8,
    ) -> None:
        self.name = name
        self.pattern = pattern
        self.severity = severity
        self.description = description
        self.remediation = remediation
        self.cwe_id = cwe_id
        self.confidence = confidence


class ConfigScanner:
    """Scans configuration files for security misconfigurations."""

    CONFIG_EXTENSIONS = {
        ".py", ".yml", ".yaml", ".json", ".toml", ".ini", ".cfg",
        ".conf", ".env", ".properties", ".xml", ".tf",
    }
    CONFIG_FILENAMES = {
        "settings.py", "config.py", "app.py", "wsgi.py",
        "docker-compose.yml", "docker-compose.yaml", "Dockerfile",
        ".env", ".env.local", ".env.production",
        "nginx.conf", "httpd.conf", "apache2.conf",
        "application.properties", "application.yml",
    }

    def __init__(self) -> None:
        self._patterns = self._build_patterns()
        self._counter = 0

    def scan(self, target: str | Path) -> list[Vulnerability]:
        """Scan a file or directory for configuration issues."""
        target = Path(target)
        if target.is_file():
            return self._scan_file(target)
        elif target.is_dir():
            return self._scan_directory(target)
        return []

    def _scan_file(self, file_path: Path) -> list[Vulnerability]:
        if not file_path.is_file():
            return []
        if (
            file_path.suffix.lower() not in self.CONFIG_EXTENSIONS
            and file_path.name not in self.CONFIG_FILENAMES
        ):
            return []

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except (OSError, PermissionError):
            return []

        vulns: list[Vulnerability] = []
        lines = content.splitlines()

        for pat in self._patterns:
            for line_num, line in enumerate(lines, start=1):
                if pat.pattern.search(line):
                    self._counter += 1
                    vulns.append(Vulnerability(
                        id=f"VULNFIX-CFG-{self._counter:04d}",
                        title=pat.name.replace("_", " ").title(),
                        description=pat.description,
                        severity=pat.severity,
                        owasp_category=OWASPCategory.A05_SECURITY_MISCONFIGURATION,
                        file_path=str(file_path),
                        line_number=line_num,
                        code_snippet=line.strip(),
                        cwe_id=pat.cwe_id,
                        confidence=pat.confidence,
                        remediation=pat.remediation,
                    ))

        return vulns

    def _scan_directory(self, directory: Path) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        for root, dirs, files in os.walk(directory):
            dirs[:] = [
                d for d in dirs
                if not d.startswith(".")
                and d not in {"node_modules", "__pycache__", "venv", ".venv", "dist", "build", ".git"}
            ]
            for filename in files:
                file_path = Path(root) / filename
                vulns.extend(self._scan_file(file_path))
        return vulns

    @staticmethod
    def _build_patterns() -> list[_ConfigPattern]:
        return [
            # Debug mode
            _ConfigPattern(
                name="debug_mode_enabled",
                pattern=re.compile(r'''DEBUG\s*=\s*True''', re.IGNORECASE),
                severity=Severity.HIGH,
                description="Debug mode is enabled, which may expose sensitive information and stack traces in production.",
                remediation="Set DEBUG = False in production environments.",
                cwe_id="CWE-489",
                confidence=0.85,
            ),
            _ConfigPattern(
                name="debug_mode_flask",
                pattern=re.compile(r'''app\.run\s*\([^)]*debug\s*=\s*True''', re.IGNORECASE),
                severity=Severity.HIGH,
                description="Flask app running in debug mode exposes interactive debugger (Werkzeug).",
                remediation="Set debug=False in production. Use environment variable to control.",
                cwe_id="CWE-489",
                confidence=0.9,
            ),

            # Default / weak passwords
            _ConfigPattern(
                name="default_password",
                pattern=re.compile(
                    r'''(?:password|passwd|pwd)\s*[:=]\s*["\'](?:password|admin|root|123456|default|changeme|test|guest|qwerty|letmein)["\']''',
                    re.IGNORECASE,
                ),
                severity=Severity.CRITICAL,
                description="Default or commonly-used weak password detected in configuration.",
                remediation="Use strong, unique passwords. Store in environment variables or secrets manager.",
                cwe_id="CWE-521",
                confidence=0.9,
            ),
            _ConfigPattern(
                name="empty_password",
                pattern=re.compile(r'''(?:password|passwd|pwd)\s*[:=]\s*["\']["\']''', re.IGNORECASE),
                severity=Severity.CRITICAL,
                description="Empty password configured.",
                remediation="Set a strong password. Never use empty passwords.",
                cwe_id="CWE-521",
                confidence=0.9,
            ),

            # Exposed ports
            _ConfigPattern(
                name="exposed_port_bind_all",
                pattern=re.compile(r'''(?:host|bind|listen)\s*[:=]\s*["\']?0\.0\.0\.0''', re.IGNORECASE),
                severity=Severity.MEDIUM,
                description="Service bound to 0.0.0.0, exposing it on all network interfaces.",
                remediation="Bind to 127.0.0.1 or a specific interface in production.",
                cwe_id="CWE-668",
                confidence=0.75,
            ),
            _ConfigPattern(
                name="exposed_port_docker",
                pattern=re.compile(r'''ports:\s*\n?\s*-\s*["\']?0\.0\.0\.0:\d+:\d+''', re.IGNORECASE),
                severity=Severity.MEDIUM,
                description="Docker container port exposed on all interfaces.",
                remediation="Map ports to 127.0.0.1 in docker-compose: '127.0.0.1:8080:8080'.",
                cwe_id="CWE-668",
                confidence=0.8,
            ),

            # Secret key issues
            _ConfigPattern(
                name="weak_secret_key",
                pattern=re.compile(
                    r'''SECRET_KEY\s*=\s*["\'](?:secret|changeme|your-secret-key|sk-[a-z]{3,8}|xxx|key)["\']''',
                    re.IGNORECASE,
                ),
                severity=Severity.CRITICAL,
                description="Weak or placeholder SECRET_KEY detected.",
                remediation="Generate a strong random key: python -c \"import secrets; print(secrets.token_hex(32))\"",
                cwe_id="CWE-798",
                confidence=0.9,
            ),

            # HTTPS / SSL disabled
            _ConfigPattern(
                name="ssl_disabled",
                pattern=re.compile(r'''(?:SECURE_SSL_REDIRECT|SESSION_COOKIE_SECURE|CSRF_COOKIE_SECURE)\s*=\s*False''', re.IGNORECASE),
                severity=Severity.HIGH,
                description="Security-related SSL/cookie setting disabled.",
                remediation="Enable SECURE_SSL_REDIRECT, SESSION_COOKIE_SECURE, and CSRF_COOKIE_SECURE in production.",
                cwe_id="CWE-311",
                confidence=0.85,
            ),

            # Verbose error pages
            _ConfigPattern(
                name="verbose_errors",
                pattern=re.compile(r'''(?:PROPAGATE_EXCEPTIONS|TRAP_HTTP_EXCEPTIONS)\s*=\s*True''', re.IGNORECASE),
                severity=Severity.MEDIUM,
                description="Verbose exception handling enabled, may leak information.",
                remediation="Disable verbose exceptions in production.",
                cwe_id="CWE-209",
                confidence=0.7,
            ),

            # ALLOWED_HOSTS wildcard
            _ConfigPattern(
                name="allowed_hosts_wildcard",
                pattern=re.compile(r'''ALLOWED_HOSTS\s*=\s*\[?\s*["\']?\*["\']?\s*\]?'''),
                severity=Severity.MEDIUM,
                description="ALLOWED_HOSTS set to wildcard, allowing HTTP Host header attacks.",
                remediation="Set ALLOWED_HOSTS to specific domains: ALLOWED_HOSTS = ['example.com'].",
                cwe_id="CWE-16",
                confidence=0.85,
            ),

            # Exposed admin interfaces
            _ConfigPattern(
                name="exposed_admin_path",
                pattern=re.compile(r'''(?:path|url)\s*\(\s*["\']admin/?["\']''', re.IGNORECASE),
                severity=Severity.LOW,
                description="Admin interface at default '/admin/' path is easily guessable.",
                remediation="Use a custom, non-obvious URL path for admin interfaces.",
                cwe_id="CWE-16",
                confidence=0.5,
            ),

            # AWS credentials
            _ConfigPattern(
                name="aws_key_in_config",
                pattern=re.compile(r'''(?:AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY)\s*[:=]\s*["\'][A-Za-z0-9/+=]{16,}["\']'''),
                severity=Severity.CRITICAL,
                description="AWS credentials hardcoded in configuration file.",
                remediation="Use IAM roles or environment variables. Never store AWS keys in source.",
                cwe_id="CWE-798",
                confidence=0.9,
            ),

            # Database connection strings with credentials
            _ConfigPattern(
                name="database_credentials_in_url",
                pattern=re.compile(
                    r'''(?:DATABASE_URL|SQLALCHEMY_DATABASE_URI|DB_URL)\s*[:=]\s*["\'](?:postgres|mysql|mssql|oracle)://\w+:.+@''',
                    re.IGNORECASE,
                ),
                severity=Severity.HIGH,
                description="Database credentials embedded in connection string.",
                remediation="Store database credentials in environment variables or secrets manager.",
                cwe_id="CWE-798",
                confidence=0.85,
            ),
        ]

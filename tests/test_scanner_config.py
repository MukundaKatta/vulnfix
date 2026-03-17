"""Tests for the configuration scanner."""

import tempfile
from pathlib import Path

from vulnfix.scanner.config import ConfigScanner


class TestConfigScanner:
    def setup_method(self):
        self.scanner = ConfigScanner()

    def _scan_content(self, content: str, filename: str = "settings.py") -> list:
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / filename
            p.write_text(content)
            return self.scanner.scan(str(p))

    def test_debug_mode(self):
        vulns = self._scan_content("DEBUG = True")
        assert len(vulns) >= 1
        assert any("debug" in v.title.lower() for v in vulns)

    def test_debug_mode_flask(self):
        vulns = self._scan_content('app.run(host="0.0.0.0", debug=True)')
        assert len(vulns) >= 1

    def test_default_password(self):
        vulns = self._scan_content('password = "admin"')
        assert len(vulns) >= 1
        assert any(v.cwe_id == "CWE-521" for v in vulns)

    def test_empty_password(self):
        vulns = self._scan_content('password = ""')
        assert len(vulns) >= 1

    def test_exposed_port(self):
        vulns = self._scan_content('host = "0.0.0.0"', filename="config.py")
        assert len(vulns) >= 1
        assert any(v.cwe_id == "CWE-668" for v in vulns)

    def test_weak_secret_key(self):
        vulns = self._scan_content('SECRET_KEY = "changeme"')
        assert len(vulns) >= 1
        assert any(v.cwe_id == "CWE-798" for v in vulns)

    def test_ssl_disabled(self):
        vulns = self._scan_content("SECURE_SSL_REDIRECT = False")
        assert len(vulns) >= 1

    def test_allowed_hosts_wildcard(self):
        vulns = self._scan_content('ALLOWED_HOSTS = ["*"]')
        assert len(vulns) >= 1

    def test_aws_key(self):
        vulns = self._scan_content('AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"')
        assert len(vulns) >= 1
        assert any(v.cwe_id == "CWE-798" for v in vulns)

    def test_database_url_with_creds(self):
        vulns = self._scan_content('DATABASE_URL = "postgres://admin:secret@localhost/db"')
        assert len(vulns) >= 1

    def test_clean_config(self):
        content = """
import os
DEBUG = os.environ.get("DEBUG", "False")
SECRET_KEY = os.environ["SECRET_KEY"]
"""
        vulns = self._scan_content(content)
        assert len(vulns) == 0

    def test_scan_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "settings.py"
            p.write_text("DEBUG = True\n")
            vulns = self.scanner.scan(tmpdir)
            assert len(vulns) >= 1

    def test_scan_nonexistent(self):
        vulns = self.scanner.scan("/nonexistent/path")
        assert vulns == []

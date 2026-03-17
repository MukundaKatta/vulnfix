"""Tests for the CLI interface."""

import tempfile
from pathlib import Path

from click.testing import CliRunner

from vulnfix.cli import cli


class TestCLI:
    def setup_method(self):
        self.runner = CliRunner()

    def test_version(self):
        result = self.runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "vulnfix" in result.output.lower()

    def test_help(self):
        result = self.runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "VULNFIX" in result.output

    def test_scan_help(self):
        result = self.runner.invoke(cli, ["scan", "--help"])
        assert result.exit_code == 0

    def test_scan_code(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "vuln.py"
            p.write_text('cursor.execute(f"SELECT * FROM users WHERE id = {uid}")')
            result = self.runner.invoke(cli, ["scan", "code", tmpdir])
            assert result.exit_code == 0

    def test_scan_code_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "vuln.py"
            p.write_text('password = "admin123"')
            result = self.runner.invoke(cli, ["scan", "code", tmpdir, "--format", "json"])
            assert result.exit_code == 0

    def test_scan_deps(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("django==4.0.0\n")
            f.flush()
            result = self.runner.invoke(cli, ["scan", "deps", f.name])
            assert result.exit_code == 0

    def test_scan_config(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "settings.py"
            p.write_text("DEBUG = True\n")
            result = self.runner.invoke(cli, ["scan", "config", tmpdir])
            assert result.exit_code == 0

    def test_scan_all(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "app.py"
            p.write_text('DEBUG = True\npassword = "admin"\n')
            result = self.runner.invoke(cli, ["scan", "all", tmpdir])
            assert result.exit_code == 0

    def test_report_command(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "settings.py"
            p.write_text("DEBUG = True\n")
            result = self.runner.invoke(cli, ["report", tmpdir])
            assert result.exit_code == 0

    def test_report_json_output(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "settings.py"
            p.write_text("DEBUG = True\n")
            out = Path(tmpdir) / "report.json"
            result = self.runner.invoke(cli, ["report", tmpdir, "-o", str(out)])
            assert result.exit_code == 0
            assert out.exists()

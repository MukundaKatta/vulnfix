"""Tests for the code scanner."""

import tempfile
from pathlib import Path

from vulnfix.models import Severity
from vulnfix.scanner.code import CodeScanner


class TestCodeScanner:
    def setup_method(self):
        self.scanner = CodeScanner()

    def _scan_content(self, content: str, suffix: str = ".py") -> list:
        with tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False) as f:
            f.write(content)
            f.flush()
            return self.scanner.scan_file(f.name)

    def test_sql_injection_fstring(self):
        code = '''cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")'''
        vulns = self._scan_content(code)
        assert len(vulns) >= 1
        assert any("sql" in v.title.lower() for v in vulns)
        assert any(v.cwe_id == "CWE-89" for v in vulns)

    def test_sql_injection_concat(self):
        code = '''cursor.execute("SELECT * FROM users WHERE id = " + user_id)'''
        vulns = self._scan_content(code)
        assert len(vulns) >= 1
        assert any(v.cwe_id == "CWE-89" for v in vulns)

    def test_sql_injection_format(self):
        code = '''cursor.execute("SELECT * FROM users WHERE id = {}".format(user_id))'''
        vulns = self._scan_content(code)
        assert len(vulns) >= 1

    def test_xss_innerhtml(self):
        code = '''element.innerHTML = userInput;'''
        vulns = self._scan_content(code, suffix=".js")
        assert len(vulns) >= 1
        assert any(v.cwe_id == "CWE-79" for v in vulns)

    def test_xss_document_write(self):
        code = '''document.write(data);'''
        vulns = self._scan_content(code, suffix=".js")
        assert len(vulns) >= 1

    def test_pickle_load(self):
        code = '''data = pickle.load(open("data.pkl", "rb"))'''
        vulns = self._scan_content(code)
        assert len(vulns) >= 1
        assert any(v.cwe_id == "CWE-502" for v in vulns)

    def test_yaml_unsafe_load(self):
        code = '''data = yaml.load(content)'''
        vulns = self._scan_content(code)
        assert len(vulns) >= 1
        assert any(v.cwe_id == "CWE-502" for v in vulns)

    def test_hardcoded_password(self):
        code = '''password = "supersecret123"'''
        vulns = self._scan_content(code)
        assert len(vulns) >= 1
        assert any(v.cwe_id == "CWE-798" for v in vulns)

    def test_weak_hash_md5(self):
        code = '''digest = hashlib.md5(data.encode()).hexdigest()'''
        vulns = self._scan_content(code)
        assert len(vulns) >= 1
        assert any(v.cwe_id == "CWE-328" for v in vulns)

    def test_jwt_no_verify(self):
        code = '''payload = jwt.decode(token, verify=False)'''
        vulns = self._scan_content(code)
        assert len(vulns) >= 1
        assert any(v.cwe_id == "CWE-345" for v in vulns)

    def test_eval_with_input(self):
        code = '''result = eval(user_input)'''
        vulns = self._scan_content(code)
        assert len(vulns) >= 1
        assert any(v.cwe_id == "CWE-95" for v in vulns)

    def test_os_command_injection(self):
        code = '''os.system(f"ping {user_input}")'''
        vulns = self._scan_content(code)
        assert len(vulns) >= 1
        assert any(v.cwe_id == "CWE-78" for v in vulns)

    def test_csrf_exempt(self):
        code = '''@csrf_exempt\ndef my_view(request):'''
        vulns = self._scan_content(code)
        assert len(vulns) >= 1
        assert any(v.cwe_id == "CWE-352" for v in vulns)

    def test_ssl_no_verify(self):
        code = '''requests.get(url, verify=False)'''
        vulns = self._scan_content(code)
        assert len(vulns) >= 1
        assert any(v.cwe_id == "CWE-295" for v in vulns)

    def test_clean_code_no_findings(self):
        code = '''
def get_user(user_id):
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    return cursor.fetchone()
'''
        vulns = self._scan_content(code)
        sql_vulns = [v for v in vulns if v.cwe_id == "CWE-89"]
        assert len(sql_vulns) == 0

    def test_scan_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "vuln.py"
            p.write_text('cursor.execute(f"SELECT * FROM users WHERE id = {uid}")')
            vulns = self.scanner.scan_directory(tmpdir)
            assert len(vulns) >= 1

    def test_scan_nonexistent(self):
        vulns = self.scanner.scan("/nonexistent/path/abc123")
        assert vulns == []

    def test_scan_unsupported_extension(self):
        with tempfile.NamedTemporaryFile(suffix=".xyz", mode="w", delete=False) as f:
            f.write("pickle.load(data)")
            f.flush()
            vulns = self.scanner.scan_file(f.name)
        assert vulns == []

    def test_cors_wildcard(self):
        code = '''Access-Control-Allow-Origin: *'''
        vulns = self._scan_content(code, suffix=".py")
        assert any(v.cwe_id == "CWE-942" for v in vulns)

    def test_insecure_random(self):
        code = '''token = random.random()'''
        vulns = self._scan_content(code)
        assert any(v.cwe_id == "CWE-330" for v in vulns)

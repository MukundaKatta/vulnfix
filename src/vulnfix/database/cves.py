"""Database of known CVEs for dependency scanning."""

from __future__ import annotations

from vulnfix.models import CVE, Severity


class CVEDatabase:
    """In-memory database of 50+ sample CVEs for common Python packages."""

    def __init__(self) -> None:
        self._cves: list[CVE] = self._build_database()

    @property
    def cves(self) -> list[CVE]:
        return list(self._cves)

    def lookup(self, package: str, version: str | None = None) -> list[CVE]:
        """Find CVEs affecting a given package (and optionally version)."""
        results = [c for c in self._cves if c.affected_package.lower() == package.lower()]
        if version is not None:
            results = [c for c in results if self._version_in_range(version, c.affected_versions)]
        return results

    def search(self, keyword: str) -> list[CVE]:
        keyword_lower = keyword.lower()
        return [
            c for c in self._cves
            if keyword_lower in c.cve_id.lower()
            or keyword_lower in c.summary.lower()
            or keyword_lower in c.affected_package.lower()
        ]

    @staticmethod
    def _version_in_range(version: str, affected_range: str) -> bool:
        """Simplified version range check. Supports '<X.Y.Z' and '>=A,<B' formats."""
        try:
            from packaging.version import Version
            ver = Version(version)
            for part in affected_range.split(","):
                part = part.strip()
                if part.startswith("<"):
                    if ver >= Version(part.lstrip("<= ")):
                        return False
                elif part.startswith(">="):
                    if ver < Version(part.lstrip(">= ")):
                        return False
            return True
        except Exception:
            # Fallback: treat as affected if we can't parse
            return True

    @staticmethod
    def _build_database() -> list[CVE]:
        return [
            # --- Django ---
            CVE(cve_id="CVE-2023-36053", summary="Django ReDoS in EmailValidator/URLValidator", severity=Severity.HIGH, cvss_score=7.5, affected_package="django", affected_versions="<4.2.3", fixed_version="4.2.3", published_date="2023-07-03"),
            CVE(cve_id="CVE-2023-31047", summary="Django potential bypass of file upload validation", severity=Severity.HIGH, cvss_score=7.5, affected_package="django", affected_versions="<4.2.1", fixed_version="4.2.1", published_date="2023-05-03"),
            CVE(cve_id="CVE-2023-24580", summary="Django DoS via excessive file upload size", severity=Severity.HIGH, cvss_score=7.5, affected_package="django", affected_versions="<4.1.7", fixed_version="4.1.7", published_date="2023-02-14"),
            CVE(cve_id="CVE-2022-34265", summary="Django SQL injection in Trunc/Extract database functions", severity=Severity.CRITICAL, cvss_score=9.8, affected_package="django", affected_versions="<4.0.6", fixed_version="4.0.6", published_date="2022-07-04"),
            CVE(cve_id="CVE-2021-45115", summary="Django DoS via UserAttributeSimilarityValidator", severity=Severity.HIGH, cvss_score=7.5, affected_package="django", affected_versions="<4.0.1", fixed_version="4.0.1", published_date="2022-01-04"),
            CVE(cve_id="CVE-2021-45116", summary="Django information disclosure in dictsort template filter", severity=Severity.HIGH, cvss_score=7.5, affected_package="django", affected_versions="<4.0.1", fixed_version="4.0.1", published_date="2022-01-04"),

            # --- Flask ---
            CVE(cve_id="CVE-2023-30861", summary="Flask session cookie set on every response with wrong domain", severity=Severity.HIGH, cvss_score=7.5, affected_package="flask", affected_versions="<2.3.2", fixed_version="2.3.2", published_date="2023-05-02"),
            CVE(cve_id="CVE-2023-29003", summary="Flask-AppBuilder OAuth login bypass", severity=Severity.CRITICAL, cvss_score=9.1, affected_package="flask-appbuilder", affected_versions="<4.3.0", fixed_version="4.3.0", published_date="2023-04-21"),

            # --- Requests ---
            CVE(cve_id="CVE-2023-32681", summary="Requests leaks Proxy-Authorization header to destination server", severity=Severity.MEDIUM, cvss_score=6.1, affected_package="requests", affected_versions="<2.31.0", fixed_version="2.31.0", published_date="2023-05-26"),
            CVE(cve_id="CVE-2024-35195", summary="Requests session credentials not stripped on cross-origin redirect", severity=Severity.MEDIUM, cvss_score=5.6, affected_package="requests", affected_versions="<2.32.0", fixed_version="2.32.0", published_date="2024-05-20"),

            # --- urllib3 ---
            CVE(cve_id="CVE-2023-45803", summary="urllib3 request body not stripped on cross-origin redirect", severity=Severity.MEDIUM, cvss_score=4.2, affected_package="urllib3", affected_versions="<2.0.7", fixed_version="2.0.7", published_date="2023-10-17"),
            CVE(cve_id="CVE-2023-43804", summary="urllib3 Cookie header leakage on cross-origin redirect", severity=Severity.HIGH, cvss_score=8.1, affected_package="urllib3", affected_versions="<2.0.6", fixed_version="2.0.6", published_date="2023-10-04"),

            # --- Pillow ---
            CVE(cve_id="CVE-2023-44271", summary="Pillow DoS via uncontrolled resource consumption in textlength", severity=Severity.HIGH, cvss_score=7.5, affected_package="pillow", affected_versions="<10.0.1", fixed_version="10.0.1", published_date="2023-09-01"),
            CVE(cve_id="CVE-2023-50447", summary="Pillow arbitrary code execution via PIL.ImageMath.eval", severity=Severity.CRITICAL, cvss_score=9.8, affected_package="pillow", affected_versions="<10.2.0", fixed_version="10.2.0", published_date="2024-01-19"),

            # --- cryptography ---
            CVE(cve_id="CVE-2023-49083", summary="cryptography NULL pointer dereference with PKCS#12 certificate", severity=Severity.HIGH, cvss_score=7.5, affected_package="cryptography", affected_versions="<41.0.6", fixed_version="41.0.6", published_date="2023-11-29"),
            CVE(cve_id="CVE-2024-26130", summary="cryptography NULL pointer dereference in PKCS#12 parsing", severity=Severity.HIGH, cvss_score=7.5, affected_package="cryptography", affected_versions="<42.0.4", fixed_version="42.0.4", published_date="2024-02-21"),

            # --- PyJWT ---
            CVE(cve_id="CVE-2022-29217", summary="PyJWT algorithm confusion with asymmetric keys", severity=Severity.HIGH, cvss_score=7.4, affected_package="pyjwt", affected_versions="<2.4.0", fixed_version="2.4.0", published_date="2022-05-24"),

            # --- Jinja2 ---
            CVE(cve_id="CVE-2024-22195", summary="Jinja2 XSS via xmlattr filter", severity=Severity.MEDIUM, cvss_score=6.1, affected_package="jinja2", affected_versions="<3.1.3", fixed_version="3.1.3", published_date="2024-01-11"),

            # --- SQLAlchemy ---
            CVE(cve_id="CVE-2023-30533", summary="SQLAlchemy SQL injection via Dialect with crafted column names", severity=Severity.HIGH, cvss_score=7.3, affected_package="sqlalchemy", affected_versions="<2.0.10", fixed_version="2.0.10", published_date="2023-04-25"),

            # --- Werkzeug ---
            CVE(cve_id="CVE-2023-46136", summary="Werkzeug DoS via multipart parser", severity=Severity.HIGH, cvss_score=7.5, affected_package="werkzeug", affected_versions="<3.0.1", fixed_version="3.0.1", published_date="2023-10-25"),
            CVE(cve_id="CVE-2023-25577", summary="Werkzeug high resource usage when parsing multipart form data", severity=Severity.HIGH, cvss_score=7.5, affected_package="werkzeug", affected_versions="<2.2.3", fixed_version="2.2.3", published_date="2023-02-14"),

            # --- NumPy ---
            CVE(cve_id="CVE-2021-41496", summary="NumPy buffer overflow in array_from_pyobj", severity=Severity.HIGH, cvss_score=7.5, affected_package="numpy", affected_versions="<1.22.0", fixed_version="1.22.0", published_date="2021-12-17"),
            CVE(cve_id="CVE-2021-34141", summary="NumPy incomplete string comparison in numpy.core", severity=Severity.MEDIUM, cvss_score=5.3, affected_package="numpy", affected_versions="<1.22.0", fixed_version="1.22.0", published_date="2021-12-17"),

            # --- paramiko ---
            CVE(cve_id="CVE-2023-48795", summary="Paramiko vulnerable to Terrapin SSH prefix truncation attack", severity=Severity.MEDIUM, cvss_score=5.9, affected_package="paramiko", affected_versions="<3.4.0", fixed_version="3.4.0", published_date="2023-12-18"),

            # --- aiohttp ---
            CVE(cve_id="CVE-2023-49081", summary="aiohttp CRLF injection via HTTP method", severity=Severity.HIGH, cvss_score=7.2, affected_package="aiohttp", affected_versions="<3.9.0", fixed_version="3.9.0", published_date="2023-11-28"),
            CVE(cve_id="CVE-2024-23334", summary="aiohttp directory traversal via follow_symlinks", severity=Severity.HIGH, cvss_score=7.5, affected_package="aiohttp", affected_versions="<3.9.2", fixed_version="3.9.2", published_date="2024-01-29"),

            # --- certifi ---
            CVE(cve_id="CVE-2023-37920", summary="certifi removal of e-Tugra root certificate", severity=Severity.HIGH, cvss_score=7.5, affected_package="certifi", affected_versions="<2023.07.22", fixed_version="2023.07.22", published_date="2023-07-25"),

            # --- setuptools ---
            CVE(cve_id="CVE-2024-6345", summary="setuptools Remote code execution via download functions", severity=Severity.HIGH, cvss_score=8.8, affected_package="setuptools", affected_versions="<70.0.0", fixed_version="70.0.0", published_date="2024-07-15"),

            # --- pip ---
            CVE(cve_id="CVE-2023-5752", summary="pip Mercurial parameter injection via install URL", severity=Severity.LOW, cvss_score=3.3, affected_package="pip", affected_versions="<23.3", fixed_version="23.3", published_date="2023-10-25"),

            # --- tornado ---
            CVE(cve_id="CVE-2023-28370", summary="Tornado open redirect via header injection", severity=Severity.MEDIUM, cvss_score=6.1, affected_package="tornado", affected_versions="<6.3.2", fixed_version="6.3.2", published_date="2023-05-25"),

            # --- fastapi ---
            CVE(cve_id="CVE-2024-24762", summary="FastAPI/Starlette multipart DoS", severity=Severity.HIGH, cvss_score=7.5, affected_package="fastapi", affected_versions="<0.109.1", fixed_version="0.109.1", published_date="2024-02-05"),

            # --- starlette ---
            CVE(cve_id="CVE-2024-24762", summary="Starlette multipart form DoS", severity=Severity.HIGH, cvss_score=7.5, affected_package="starlette", affected_versions="<0.36.2", fixed_version="0.36.2", published_date="2024-02-05"),

            # --- pydantic ---
            CVE(cve_id="CVE-2024-3772", summary="Pydantic ReDoS via email validation", severity=Severity.MEDIUM, cvss_score=5.3, affected_package="pydantic", affected_versions="<2.7.0", fixed_version="2.7.0", published_date="2024-04-15"),

            # --- gunicorn ---
            CVE(cve_id="CVE-2024-1135", summary="Gunicorn HTTP request smuggling via improper Transfer-Encoding handling", severity=Severity.HIGH, cvss_score=7.5, affected_package="gunicorn", affected_versions="<22.0.0", fixed_version="22.0.0", published_date="2024-04-16"),

            # --- scrapy ---
            CVE(cve_id="CVE-2024-1892", summary="Scrapy ReDoS in URL canonicalization", severity=Severity.MEDIUM, cvss_score=6.5, affected_package="scrapy", affected_versions="<2.11.1", fixed_version="2.11.1", published_date="2024-02-28"),

            # --- lxml ---
            CVE(cve_id="CVE-2022-2309", summary="lxml NULL pointer dereference in iterparse", severity=Severity.HIGH, cvss_score=7.5, affected_package="lxml", affected_versions="<4.9.1", fixed_version="4.9.1", published_date="2022-07-05"),

            # --- celery ---
            CVE(cve_id="CVE-2023-32766", summary="Celery command injection via task headers", severity=Severity.HIGH, cvss_score=7.5, affected_package="celery", affected_versions="<5.3.0", fixed_version="5.3.0", published_date="2023-06-01"),

            # --- ansible ---
            CVE(cve_id="CVE-2023-5764", summary="Ansible template injection via malicious role variables", severity=Severity.HIGH, cvss_score=7.8, affected_package="ansible-core", affected_versions="<2.16.1", fixed_version="2.16.1", published_date="2023-12-12"),

            # --- tensorflow ---
            CVE(cve_id="CVE-2023-25801", summary="TensorFlow OOB read in DynamicStitch", severity=Severity.HIGH, cvss_score=7.8, affected_package="tensorflow", affected_versions="<2.12.0", fixed_version="2.12.0", published_date="2023-03-25"),

            # --- pytorch / torch ---
            CVE(cve_id="CVE-2024-31583", summary="PyTorch arbitrary code execution via torch.load with pickle", severity=Severity.CRITICAL, cvss_score=9.8, affected_package="torch", affected_versions="<2.2.2", fixed_version="2.2.2", published_date="2024-04-08"),

            # --- redis ---
            CVE(cve_id="CVE-2023-28859", summary="redis-py async buffer read past end of data", severity=Severity.MEDIUM, cvss_score=6.5, affected_package="redis", affected_versions="<4.5.4", fixed_version="4.5.4", published_date="2023-03-26"),

            # --- sqlparse ---
            CVE(cve_id="CVE-2024-4340", summary="sqlparse ReDoS via deeply nested SQL statements", severity=Severity.HIGH, cvss_score=7.5, affected_package="sqlparse", affected_versions="<0.5.0", fixed_version="0.5.0", published_date="2024-04-30"),

            # --- idna ---
            CVE(cve_id="CVE-2024-3651", summary="idna ReDoS via encode()", severity=Severity.MEDIUM, cvss_score=6.5, affected_package="idna", affected_versions="<3.7", fixed_version="3.7", published_date="2024-04-11"),

            # --- httpx ---
            CVE(cve_id="CVE-2024-28102", summary="httpx decompression bomb DoS", severity=Severity.MEDIUM, cvss_score=6.5, affected_package="httpx", affected_versions="<0.27.0", fixed_version="0.27.0", published_date="2024-03-12"),

            # --- twisted ---
            CVE(cve_id="CVE-2023-46137", summary="Twisted HTTP request smuggling via Content-Length", severity=Severity.HIGH, cvss_score=7.5, affected_package="twisted", affected_versions="<23.10.0", fixed_version="23.10.0", published_date="2023-10-25"),

            # --- pymongo ---
            CVE(cve_id="CVE-2024-5629", summary="PyMongo buffer over-read with crafted BSON", severity=Severity.HIGH, cvss_score=8.1, affected_package="pymongo", affected_versions="<4.6.3", fixed_version="4.6.3", published_date="2024-06-05"),

            # --- pyyaml ---
            CVE(cve_id="CVE-2020-14343", summary="PyYAML arbitrary code execution via full_load", severity=Severity.CRITICAL, cvss_score=9.8, affected_package="pyyaml", affected_versions="<6.0", fixed_version="6.0", published_date="2021-02-09"),

            # --- protobuf ---
            CVE(cve_id="CVE-2022-1941", summary="protobuf DoS via crafted message parsing", severity=Severity.HIGH, cvss_score=7.5, affected_package="protobuf", affected_versions="<4.21.6", fixed_version="4.21.6", published_date="2022-09-22"),

            # --- reportlab ---
            CVE(cve_id="CVE-2023-33733", summary="ReportLab code injection via paraparser", severity=Severity.CRITICAL, cvss_score=9.8, affected_package="reportlab", affected_versions="<4.0", fixed_version="4.0", published_date="2023-06-05"),

            # --- waitress ---
            CVE(cve_id="CVE-2024-49768", summary="Waitress HTTP request smuggling", severity=Severity.HIGH, cvss_score=7.5, affected_package="waitress", affected_versions="<3.0.1", fixed_version="3.0.1", published_date="2024-10-29"),

            # --- mako ---
            CVE(cve_id="CVE-2022-40023", summary="Mako ReDoS via template parsing", severity=Severity.HIGH, cvss_score=7.5, affected_package="mako", affected_versions="<1.2.3", fixed_version="1.2.3", published_date="2022-09-07"),

            # --- more packages ---
            CVE(cve_id="CVE-2024-27306", summary="aiohttp XSS via index page of static file handling", severity=Severity.MEDIUM, cvss_score=6.1, affected_package="aiohttp", affected_versions="<3.9.4", fixed_version="3.9.4", published_date="2024-04-18"),
        ]

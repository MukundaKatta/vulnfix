"""Regex patterns for detecting OWASP Top 10 vulnerabilities."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from vulnfix.models import OWASPCategory, Severity


@dataclass
class VulnPattern:
    """A vulnerability detection pattern."""

    name: str
    pattern: re.Pattern
    severity: Severity
    owasp_category: OWASPCategory
    cwe_id: str
    description: str
    remediation: str
    confidence: float = 0.8


class VulnerabilityPatterns:
    """Registry of regex patterns for each OWASP vulnerability category."""

    def __init__(self) -> None:
        self._patterns: list[VulnPattern] = []
        self._register_all()

    @property
    def patterns(self) -> list[VulnPattern]:
        return list(self._patterns)

    def get_by_category(self, category: OWASPCategory) -> list[VulnPattern]:
        return [p for p in self._patterns if p.owasp_category == category]

    # ------------------------------------------------------------------ #
    #  A03:2021 - Injection (SQL Injection)
    # ------------------------------------------------------------------ #
    def _register_sql_injection(self) -> None:
        self._patterns.extend([
            VulnPattern(
                name="sql_injection_string_format",
                pattern=re.compile(
                    r'''(?:execute|cursor\.execute|\.raw|\.extra)\s*\(\s*(?:f?["\'].*?%s.*?["\']|f?["\'].*?\{.*?\}.*?["\'])\s*%\s*\(''',
                    re.IGNORECASE,
                ),
                severity=Severity.CRITICAL,
                owasp_category=OWASPCategory.A03_INJECTION,
                cwe_id="CWE-89",
                description="SQL query built with string formatting is vulnerable to SQL injection.",
                remediation="Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
                confidence=0.9,
            ),
            VulnPattern(
                name="sql_injection_fstring",
                pattern=re.compile(
                    r'''(?:execute|cursor\.execute|\.raw|\.extra)\s*\(\s*f["\'].*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE).*\{.*\}''',
                    re.IGNORECASE,
                ),
                severity=Severity.CRITICAL,
                owasp_category=OWASPCategory.A03_INJECTION,
                cwe_id="CWE-89",
                description="SQL query built with f-string is vulnerable to SQL injection.",
                remediation="Use parameterized queries instead of f-strings for SQL.",
                confidence=0.95,
            ),
            VulnPattern(
                name="sql_injection_concat",
                pattern=re.compile(
                    r'''(?:execute|cursor\.execute)\s*\(\s*["\'].*(?:SELECT|INSERT|UPDATE|DELETE).*["\']\s*\+\s*''',
                    re.IGNORECASE,
                ),
                severity=Severity.CRITICAL,
                owasp_category=OWASPCategory.A03_INJECTION,
                cwe_id="CWE-89",
                description="SQL query built with string concatenation is vulnerable to SQL injection.",
                remediation="Use parameterized queries instead of string concatenation.",
                confidence=0.9,
            ),
            VulnPattern(
                name="sql_injection_format_method",
                pattern=re.compile(
                    r'''(?:execute|cursor\.execute)\s*\(\s*["\'].*(?:SELECT|INSERT|UPDATE|DELETE).*["\']\.format\s*\(''',
                    re.IGNORECASE,
                ),
                severity=Severity.CRITICAL,
                owasp_category=OWASPCategory.A03_INJECTION,
                cwe_id="CWE-89",
                description="SQL query built with .format() is vulnerable to SQL injection.",
                remediation="Use parameterized queries instead of .format().",
                confidence=0.9,
            ),
        ])

    # ------------------------------------------------------------------ #
    #  A03:2021 - Injection (XSS)
    # ------------------------------------------------------------------ #
    def _register_xss(self) -> None:
        self._patterns.extend([
            VulnPattern(
                name="xss_innerhtml",
                pattern=re.compile(r'''\.innerHTML\s*=\s*(?!['"]<)'''),
                severity=Severity.HIGH,
                owasp_category=OWASPCategory.A03_INJECTION,
                cwe_id="CWE-79",
                description="Setting innerHTML with dynamic content enables XSS attacks.",
                remediation="Use textContent or DOMPurify.sanitize() before assigning to innerHTML.",
                confidence=0.8,
            ),
            VulnPattern(
                name="xss_document_write",
                pattern=re.compile(r'''document\.write\s*\('''),
                severity=Severity.HIGH,
                owasp_category=OWASPCategory.A03_INJECTION,
                cwe_id="CWE-79",
                description="document.write() with user input enables XSS.",
                remediation="Avoid document.write(). Use DOM manipulation with textContent.",
                confidence=0.7,
            ),
            VulnPattern(
                name="xss_mark_safe",
                pattern=re.compile(r'''mark_safe\s*\(.*(?:request|input|param|user)''', re.IGNORECASE),
                severity=Severity.HIGH,
                owasp_category=OWASPCategory.A03_INJECTION,
                cwe_id="CWE-79",
                description="mark_safe() with user-controlled data can lead to XSS.",
                remediation="Never use mark_safe() with user input. Sanitize first with bleach or escape.",
                confidence=0.85,
            ),
            VulnPattern(
                name="xss_jinja_raw",
                pattern=re.compile(r'''\{\{.*\|.*safe\s*\}\}'''),
                severity=Severity.MEDIUM,
                owasp_category=OWASPCategory.A03_INJECTION,
                cwe_id="CWE-79",
                description="Jinja2 |safe filter disables autoescaping, risking XSS.",
                remediation="Remove |safe filter or sanitize input before marking safe.",
                confidence=0.75,
            ),
            VulnPattern(
                name="xss_render_template_string",
                pattern=re.compile(r'''render_template_string\s*\(.*(?:request|input|param)''', re.IGNORECASE),
                severity=Severity.CRITICAL,
                owasp_category=OWASPCategory.A03_INJECTION,
                cwe_id="CWE-79",
                description="render_template_string with user input enables server-side template injection.",
                remediation="Use render_template() with static template files instead.",
                confidence=0.9,
            ),
        ])

    # ------------------------------------------------------------------ #
    #  A05:2021 - Security Misconfiguration (CSRF)
    # ------------------------------------------------------------------ #
    def _register_csrf(self) -> None:
        self._patterns.extend([
            VulnPattern(
                name="csrf_exempt_decorator",
                pattern=re.compile(r'''@csrf_exempt'''),
                severity=Severity.MEDIUM,
                owasp_category=OWASPCategory.A05_SECURITY_MISCONFIGURATION,
                cwe_id="CWE-352",
                description="CSRF protection disabled via @csrf_exempt decorator.",
                remediation="Remove @csrf_exempt and use proper CSRF tokens in forms.",
                confidence=0.9,
            ),
            VulnPattern(
                name="csrf_disabled_config",
                pattern=re.compile(r'''WTF_CSRF_ENABLED\s*=\s*False''', re.IGNORECASE),
                severity=Severity.HIGH,
                owasp_category=OWASPCategory.A05_SECURITY_MISCONFIGURATION,
                cwe_id="CWE-352",
                description="CSRF protection globally disabled in Flask-WTF configuration.",
                remediation="Set WTF_CSRF_ENABLED = True.",
                confidence=0.95,
            ),
            VulnPattern(
                name="csrf_middleware_missing",
                pattern=re.compile(
                    r'''MIDDLEWARE\s*=\s*\[(?:(?!CsrfViewMiddleware).)*\]''',
                    re.DOTALL,
                ),
                severity=Severity.HIGH,
                owasp_category=OWASPCategory.A05_SECURITY_MISCONFIGURATION,
                cwe_id="CWE-352",
                description="Django CsrfViewMiddleware not found in MIDDLEWARE list.",
                remediation="Add 'django.middleware.csrf.CsrfViewMiddleware' to MIDDLEWARE.",
                confidence=0.7,
            ),
        ])

    # ------------------------------------------------------------------ #
    #  A08:2021 - Insecure Deserialization
    # ------------------------------------------------------------------ #
    def _register_insecure_deserialization(self) -> None:
        self._patterns.extend([
            VulnPattern(
                name="pickle_load",
                pattern=re.compile(r'''pickle\.loads?\s*\('''),
                severity=Severity.CRITICAL,
                owasp_category=OWASPCategory.A08_DATA_INTEGRITY_FAILURES,
                cwe_id="CWE-502",
                description="pickle.load() on untrusted data allows arbitrary code execution.",
                remediation="Use json.loads() or a safe deserialization library. Never unpickle untrusted data.",
                confidence=0.85,
            ),
            VulnPattern(
                name="yaml_unsafe_load",
                pattern=re.compile(r'''yaml\.load\s*\([^)]*(?!Loader\s*=\s*yaml\.SafeLoader)'''),
                severity=Severity.HIGH,
                owasp_category=OWASPCategory.A08_DATA_INTEGRITY_FAILURES,
                cwe_id="CWE-502",
                description="yaml.load() without SafeLoader allows arbitrary code execution.",
                remediation="Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader).",
                confidence=0.85,
            ),
            VulnPattern(
                name="marshal_loads",
                pattern=re.compile(r'''marshal\.loads?\s*\('''),
                severity=Severity.HIGH,
                owasp_category=OWASPCategory.A08_DATA_INTEGRITY_FAILURES,
                cwe_id="CWE-502",
                description="marshal.load() is not safe for untrusted data.",
                remediation="Use json or a safe serialization format instead of marshal.",
                confidence=0.8,
            ),
            VulnPattern(
                name="shelve_open",
                pattern=re.compile(r'''shelve\.open\s*\('''),
                severity=Severity.MEDIUM,
                owasp_category=OWASPCategory.A08_DATA_INTEGRITY_FAILURES,
                cwe_id="CWE-502",
                description="shelve uses pickle internally and is unsafe for untrusted data.",
                remediation="Use a database or JSON for storage instead of shelve.",
                confidence=0.7,
            ),
        ])

    # ------------------------------------------------------------------ #
    #  A07:2021 - Identification and Authentication Failures
    # ------------------------------------------------------------------ #
    def _register_broken_auth(self) -> None:
        self._patterns.extend([
            VulnPattern(
                name="hardcoded_password",
                pattern=re.compile(
                    r'''(?:password|passwd|pwd|secret|api_key|apikey|token)\s*=\s*["\'][^"\']{4,}["\']''',
                    re.IGNORECASE,
                ),
                severity=Severity.HIGH,
                owasp_category=OWASPCategory.A07_AUTH_FAILURES,
                cwe_id="CWE-798",
                description="Hardcoded credential detected in source code.",
                remediation="Store secrets in environment variables or a secrets manager (e.g. AWS Secrets Manager, HashiCorp Vault).",
                confidence=0.7,
            ),
            VulnPattern(
                name="weak_hash_md5",
                pattern=re.compile(r'''(?:hashlib\.md5|MD5\.new|md5\s*\()''', re.IGNORECASE),
                severity=Severity.HIGH,
                owasp_category=OWASPCategory.A07_AUTH_FAILURES,
                cwe_id="CWE-328",
                description="MD5 is cryptographically broken and should not be used for passwords or integrity.",
                remediation="Use bcrypt, scrypt, or argon2 for passwords; SHA-256+ for integrity checks.",
                confidence=0.85,
            ),
            VulnPattern(
                name="weak_hash_sha1",
                pattern=re.compile(r'''(?:hashlib\.sha1|SHA1\.new|sha1\s*\()''', re.IGNORECASE),
                severity=Severity.MEDIUM,
                owasp_category=OWASPCategory.A07_AUTH_FAILURES,
                cwe_id="CWE-328",
                description="SHA-1 is deprecated for security purposes due to collision attacks.",
                remediation="Use SHA-256 or stronger for integrity; bcrypt/argon2 for passwords.",
                confidence=0.8,
            ),
            VulnPattern(
                name="jwt_no_verify",
                pattern=re.compile(r'''jwt\.decode\s*\([^)]*verify\s*=\s*False''', re.IGNORECASE),
                severity=Severity.CRITICAL,
                owasp_category=OWASPCategory.A07_AUTH_FAILURES,
                cwe_id="CWE-345",
                description="JWT decoded without signature verification.",
                remediation="Always verify JWT signatures: jwt.decode(token, key, algorithms=['HS256']).",
                confidence=0.95,
            ),
            VulnPattern(
                name="jwt_none_algorithm",
                pattern=re.compile(
                    r'''jwt\.(?:encode|decode)\s*\([^)]*algorithms?\s*=\s*\[?\s*["\']none["\']''',
                    re.IGNORECASE,
                ),
                severity=Severity.CRITICAL,
                owasp_category=OWASPCategory.A07_AUTH_FAILURES,
                cwe_id="CWE-345",
                description="JWT using 'none' algorithm bypasses signature verification entirely.",
                remediation="Never allow 'none' algorithm. Use HS256 or RS256.",
                confidence=0.95,
            ),
        ])

    # ------------------------------------------------------------------ #
    #  A02:2021 - Cryptographic Failures
    # ------------------------------------------------------------------ #
    def _register_crypto_failures(self) -> None:
        self._patterns.extend([
            VulnPattern(
                name="insecure_random",
                pattern=re.compile(r'''random\.(?:random|randint|choice|randrange)\s*\('''),
                severity=Severity.MEDIUM,
                owasp_category=OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
                cwe_id="CWE-330",
                description="Using random module for security-sensitive operations. It is not cryptographically secure.",
                remediation="Use secrets module: secrets.token_hex(), secrets.randbelow(), etc.",
                confidence=0.6,
            ),
            VulnPattern(
                name="des_encryption",
                pattern=re.compile(r'''DES\.new|DES3\.new|Blowfish\.new''', re.IGNORECASE),
                severity=Severity.HIGH,
                owasp_category=OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
                cwe_id="CWE-327",
                description="Using deprecated/weak encryption algorithm (DES/3DES/Blowfish).",
                remediation="Use AES-256-GCM or ChaCha20-Poly1305.",
                confidence=0.9,
            ),
            VulnPattern(
                name="ecb_mode",
                pattern=re.compile(r'''MODE_ECB|mode\s*=\s*["\']?ECB''', re.IGNORECASE),
                severity=Severity.HIGH,
                owasp_category=OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
                cwe_id="CWE-327",
                description="ECB mode does not provide semantic security; identical blocks produce identical ciphertext.",
                remediation="Use AES in GCM or CBC mode with proper IV handling.",
                confidence=0.9,
            ),
            VulnPattern(
                name="ssl_no_verify",
                pattern=re.compile(r'''verify\s*=\s*False|CERT_NONE|check_hostname\s*=\s*False'''),
                severity=Severity.HIGH,
                owasp_category=OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
                cwe_id="CWE-295",
                description="TLS/SSL certificate verification disabled, enabling man-in-the-middle attacks.",
                remediation="Always verify SSL certificates: requests.get(url, verify=True).",
                confidence=0.8,
            ),
        ])

    # ------------------------------------------------------------------ #
    #  A01:2021 - Broken Access Control
    # ------------------------------------------------------------------ #
    def _register_broken_access_control(self) -> None:
        self._patterns.extend([
            VulnPattern(
                name="path_traversal",
                pattern=re.compile(
                    r'''open\s*\(\s*(?:request\.|input\(|sys\.argv|os\.environ)''',
                    re.IGNORECASE,
                ),
                severity=Severity.HIGH,
                owasp_category=OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
                cwe_id="CWE-22",
                description="File opened with user-controlled path, enabling path traversal.",
                remediation="Validate and sanitize file paths. Use os.path.abspath() and check against allowed directories.",
                confidence=0.75,
            ),
            VulnPattern(
                name="os_command_injection",
                pattern=re.compile(
                    r'''(?:os\.system|os\.popen|subprocess\.call|subprocess\.Popen|subprocess\.run)\s*\(\s*(?:f["\']|["\'].*\{|.*\+\s*(?:request|input|user))''',
                    re.IGNORECASE,
                ),
                severity=Severity.CRITICAL,
                owasp_category=OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
                cwe_id="CWE-78",
                description="OS command built with user input enables command injection.",
                remediation="Use subprocess with a list of args and shell=False. Never pass user input to os.system().",
                confidence=0.85,
            ),
            VulnPattern(
                name="eval_exec",
                pattern=re.compile(r'''(?:eval|exec)\s*\(\s*(?:request|input|user|data)''', re.IGNORECASE),
                severity=Severity.CRITICAL,
                owasp_category=OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
                cwe_id="CWE-95",
                description="eval()/exec() with user-controlled input allows arbitrary code execution.",
                remediation="Never use eval/exec with user input. Use ast.literal_eval() for safe evaluation of literals.",
                confidence=0.9,
            ),
        ])

    # ------------------------------------------------------------------ #
    #  A10:2021 - Server-Side Request Forgery
    # ------------------------------------------------------------------ #
    def _register_ssrf(self) -> None:
        self._patterns.extend([
            VulnPattern(
                name="ssrf_requests",
                pattern=re.compile(
                    r'''requests\.(?:get|post|put|delete|patch|head)\s*\(\s*(?:request\.|input\(|user)''',
                    re.IGNORECASE,
                ),
                severity=Severity.HIGH,
                owasp_category=OWASPCategory.A10_SSRF,
                cwe_id="CWE-918",
                description="HTTP request to user-controlled URL enables SSRF attacks.",
                remediation="Validate and whitelist allowed URLs/domains. Block internal IP ranges.",
                confidence=0.8,
            ),
            VulnPattern(
                name="ssrf_urllib",
                pattern=re.compile(
                    r'''urllib\.request\.urlopen\s*\(\s*(?:request\.|input\(|user)''',
                    re.IGNORECASE,
                ),
                severity=Severity.HIGH,
                owasp_category=OWASPCategory.A10_SSRF,
                cwe_id="CWE-918",
                description="URL opened with user-controlled input enables SSRF.",
                remediation="Validate and whitelist allowed URLs. Block requests to internal networks.",
                confidence=0.8,
            ),
        ])

    # ------------------------------------------------------------------ #
    #  A09:2021 - Security Logging and Monitoring Failures
    # ------------------------------------------------------------------ #
    def _register_logging_failures(self) -> None:
        self._patterns.extend([
            VulnPattern(
                name="sensitive_data_logging",
                pattern=re.compile(
                    r'''(?:log(?:ging)?\.(?:info|debug|warning|error)|print)\s*\(.*(?:password|secret|token|api_key|credit_card|ssn)''',
                    re.IGNORECASE,
                ),
                severity=Severity.MEDIUM,
                owasp_category=OWASPCategory.A09_LOGGING_FAILURES,
                cwe_id="CWE-532",
                description="Sensitive data (passwords, tokens, etc.) may be written to logs.",
                remediation="Never log sensitive data. Mask or redact secrets before logging.",
                confidence=0.65,
            ),
        ])

    # ------------------------------------------------------------------ #
    #  A04:2021 - Insecure Design
    # ------------------------------------------------------------------ #
    def _register_insecure_design(self) -> None:
        self._patterns.extend([
            VulnPattern(
                name="cors_wildcard",
                pattern=re.compile(
                    r'''(?:Access-Control-Allow-Origin|CORS_ORIGINS?|allow_origins?)\s*[:=]\s*["\']?\*["\']?''',
                    re.IGNORECASE,
                ),
                severity=Severity.MEDIUM,
                owasp_category=OWASPCategory.A04_INSECURE_DESIGN,
                cwe_id="CWE-942",
                description="CORS wildcard (*) allows any origin to access resources.",
                remediation="Specify explicit allowed origins instead of wildcard.",
                confidence=0.8,
            ),
            VulnPattern(
                name="mass_assignment",
                pattern=re.compile(
                    r'''(?:\.objects\.create|\.update)\s*\(\s*\*\*request\.(?:POST|data|json)''',
                    re.IGNORECASE,
                ),
                severity=Severity.HIGH,
                owasp_category=OWASPCategory.A04_INSECURE_DESIGN,
                cwe_id="CWE-915",
                description="Mass assignment from request data can overwrite protected fields.",
                remediation="Explicitly list allowed fields. Use serializers or forms for validation.",
                confidence=0.8,
            ),
        ])

    def _register_all(self) -> None:
        self._register_sql_injection()
        self._register_xss()
        self._register_csrf()
        self._register_insecure_deserialization()
        self._register_broken_auth()
        self._register_crypto_failures()
        self._register_broken_access_control()
        self._register_ssrf()
        self._register_logging_failures()
        self._register_insecure_design()

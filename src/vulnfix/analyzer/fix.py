"""Fix suggestion generator for detected vulnerabilities."""

from __future__ import annotations

from vulnfix.models import Fix, Vulnerability


class FixSuggester:
    """Generates code fix recommendations based on vulnerability type."""

    # Mapping from vulnerability pattern names to detailed fix info
    _FIX_TEMPLATES: dict[str, dict] = {
        "Sql Injection String Format": {
            "title": "Use parameterized SQL queries",
            "description": "Replace string formatting with parameterized queries to prevent SQL injection.",
            "original_code": 'cursor.execute("SELECT * FROM users WHERE id = %s" % (user_id,))',
            "fixed_code": 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
            "steps": [
                "Replace string formatting (%s, .format(), f-strings) in SQL with query parameters",
                "Pass values as a tuple in the second argument to execute()",
                "For ORMs, use the query builder API instead of raw SQL",
            ],
            "effort": "low",
        },
        "Sql Injection Fstring": {
            "title": "Remove f-strings from SQL queries",
            "description": "F-strings in SQL queries allow attackers to inject arbitrary SQL.",
            "original_code": 'cursor.execute(f"SELECT * FROM users WHERE name = \'{name}\'")',
            "fixed_code": 'cursor.execute("SELECT * FROM users WHERE name = %s", (name,))',
            "steps": [
                "Remove the f-string prefix from the SQL query",
                "Replace {variable} placeholders with %s (or ? for sqlite3)",
                "Pass variables as a tuple in the second argument",
            ],
            "effort": "low",
        },
        "Xss Innerhtml": {
            "title": "Sanitize content before innerHTML assignment",
            "description": "Use textContent or sanitize HTML to prevent XSS.",
            "original_code": "element.innerHTML = userInput;",
            "fixed_code": "element.textContent = userInput;\n// Or if HTML is needed:\n// element.innerHTML = DOMPurify.sanitize(userInput);",
            "steps": [
                "Replace innerHTML with textContent for plain text",
                "If HTML content is needed, use DOMPurify.sanitize()",
                "Install DOMPurify: npm install dompurify",
            ],
            "effort": "low",
        },
        "Pickle Load": {
            "title": "Replace pickle with safe deserialization",
            "description": "pickle.load() executes arbitrary code. Use JSON or a safer alternative.",
            "original_code": "data = pickle.load(file)",
            "fixed_code": "import json\ndata = json.load(file)",
            "steps": [
                "Replace pickle.load/loads with json.load/loads where possible",
                "For complex objects, use a schema-based serializer (e.g., marshmallow, pydantic)",
                "If pickle is required, only deserialize from trusted sources and use hmac to verify integrity",
            ],
            "effort": "medium",
        },
        "Yaml Unsafe Load": {
            "title": "Use yaml.safe_load instead of yaml.load",
            "description": "yaml.load() without SafeLoader allows arbitrary code execution.",
            "original_code": "data = yaml.load(content)",
            "fixed_code": "data = yaml.safe_load(content)",
            "steps": [
                "Replace yaml.load() with yaml.safe_load()",
                "Alternatively, specify the Loader: yaml.load(content, Loader=yaml.SafeLoader)",
            ],
            "effort": "low",
        },
        "Hardcoded Password": {
            "title": "Move credentials to environment variables",
            "description": "Hardcoded credentials can be extracted from source code.",
            "original_code": 'password = "mysecretpassword"',
            "fixed_code": 'import os\npassword = os.environ["DB_PASSWORD"]',
            "steps": [
                "Move all secrets to environment variables",
                "Use python-dotenv for local development: from dotenv import load_dotenv",
                "In production, use a secrets manager (AWS Secrets Manager, Vault, etc.)",
                "Add .env to .gitignore",
            ],
            "effort": "low",
        },
        "Weak Hash Md5": {
            "title": "Replace MD5 with a secure hash function",
            "description": "MD5 is broken and should not be used for security purposes.",
            "original_code": "hash_val = hashlib.md5(data).hexdigest()",
            "fixed_code": "# For passwords:\nimport bcrypt\nhash_val = bcrypt.hashpw(password.encode(), bcrypt.gensalt())\n\n# For integrity:\nhash_val = hashlib.sha256(data).hexdigest()",
            "steps": [
                "For password hashing: use bcrypt, argon2, or scrypt",
                "For data integrity: use SHA-256 or SHA-3",
                "Install bcrypt: pip install bcrypt",
            ],
            "effort": "low",
        },
        "Jwt No Verify": {
            "title": "Enable JWT signature verification",
            "description": "JWT must always be verified to prevent token forgery.",
            "original_code": "payload = jwt.decode(token, verify=False)",
            "fixed_code": 'payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])',
            "steps": [
                "Always verify JWT signatures by providing the secret key",
                "Specify allowed algorithms explicitly",
                "Handle jwt.ExpiredSignatureError and jwt.InvalidTokenError",
            ],
            "effort": "low",
        },
        "Debug Mode Enabled": {
            "title": "Disable debug mode in production",
            "description": "Debug mode exposes sensitive information and may allow code execution.",
            "original_code": "DEBUG = True",
            "fixed_code": 'import os\nDEBUG = os.environ.get("DEBUG", "False").lower() == "true"',
            "steps": [
                "Set DEBUG = False in production settings",
                "Use environment variables to control debug mode",
                "Ensure production deployment scripts set DEBUG=false",
            ],
            "effort": "low",
        },
        "Default Password": {
            "title": "Remove default passwords",
            "description": "Default passwords are the first thing attackers try.",
            "original_code": 'password = "admin"',
            "fixed_code": 'import os\npassword = os.environ["APP_PASSWORD"]',
            "steps": [
                "Remove all default/placeholder passwords from configuration",
                "Use environment variables or secrets manager",
                "Implement password complexity requirements",
            ],
            "effort": "low",
        },
        "Ssl No Verify": {
            "title": "Enable SSL certificate verification",
            "description": "Disabling SSL verification allows man-in-the-middle attacks.",
            "original_code": "requests.get(url, verify=False)",
            "fixed_code": "requests.get(url, verify=True)  # or verify='/path/to/ca-bundle.crt'",
            "steps": [
                "Remove verify=False from all HTTP requests",
                "If using a custom CA, point verify to your CA bundle",
                "Ensure all internal services use valid TLS certificates",
            ],
            "effort": "low",
        },
        "Os Command Injection": {
            "title": "Use subprocess with argument list",
            "description": "Never pass user input to shell commands.",
            "original_code": 'os.system(f"ping {user_input}")',
            "fixed_code": 'import subprocess\nsubprocess.run(["ping", user_input], shell=False, check=True)',
            "steps": [
                "Replace os.system() with subprocess.run()",
                "Pass command as a list of arguments, not a string",
                "Set shell=False (the default)",
                "Validate and sanitize user input before passing to commands",
            ],
            "effort": "medium",
        },
        "Eval Exec": {
            "title": "Remove eval/exec with user input",
            "description": "eval() and exec() with user input allows arbitrary code execution.",
            "original_code": "result = eval(user_input)",
            "fixed_code": "import ast\nresult = ast.literal_eval(user_input)  # Only safe for literals",
            "steps": [
                "Never use eval() or exec() with user-controlled input",
                "Use ast.literal_eval() for safely evaluating Python literals",
                "For math expressions, use a safe parser like simpleeval",
                "For configuration, use JSON or YAML with safe loaders",
            ],
            "effort": "medium",
        },
        "Cors Wildcard": {
            "title": "Restrict CORS to specific origins",
            "description": "CORS wildcard allows any website to make requests to your API.",
            "original_code": 'Access-Control-Allow-Origin: *',
            "fixed_code": 'Access-Control-Allow-Origin: https://yourdomain.com',
            "steps": [
                "Replace wildcard with specific allowed origins",
                "Use a whitelist of trusted domains",
                "Be especially careful with credentials: Access-Control-Allow-Credentials",
            ],
            "effort": "low",
        },
        "Csrf Exempt Decorator": {
            "title": "Remove @csrf_exempt and use CSRF tokens",
            "description": "CSRF exemption allows cross-site request forgery attacks.",
            "original_code": "@csrf_exempt\ndef my_view(request):",
            "fixed_code": "def my_view(request):\n    # CSRF token is now required\n    # In templates: {% csrf_token %}",
            "steps": [
                "Remove @csrf_exempt decorator",
                "Add {% csrf_token %} to all POST forms",
                "For AJAX, include X-CSRFToken header",
                "If this is an API endpoint, use token-based auth instead",
            ],
            "effort": "medium",
        },
    }

    def suggest(self, vuln: Vulnerability) -> Fix:
        """Generate a fix suggestion for a vulnerability."""
        template = self._FIX_TEMPLATES.get(vuln.title)

        if template:
            return Fix(
                vulnerability_id=vuln.id,
                title=template["title"],
                description=template["description"],
                original_code=template.get("original_code"),
                fixed_code=template.get("fixed_code"),
                steps=template.get("steps", []),
                effort=template.get("effort", "medium"),
            )

        # Generic fix based on remediation hint
        return Fix(
            vulnerability_id=vuln.id,
            title=f"Fix: {vuln.title}",
            description=vuln.remediation or vuln.description,
            steps=[
                vuln.remediation or "Review and fix the identified vulnerability.",
                f"Reference: {vuln.cwe_id}" if vuln.cwe_id else "Consult OWASP guidelines.",
            ],
            effort="medium",
        )

    def suggest_all(self, vulns: list[Vulnerability]) -> list[Fix]:
        """Generate fix suggestions for all vulnerabilities."""
        return [self.suggest(v) for v in vulns]

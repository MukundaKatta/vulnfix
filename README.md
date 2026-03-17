# VULNFIX - AI Vulnerability Scanner

A comprehensive Python-based vulnerability scanner that detects OWASP Top 10 vulnerabilities, checks dependencies against known CVEs, and identifies security misconfigurations.

## Features

- **Code Scanning**: Detects OWASP Top 10 vulnerabilities using regex pattern matching
  - SQL Injection, XSS, CSRF, Insecure Deserialization, Broken Authentication, and more
- **Dependency Scanning**: Checks installed packages against a database of known CVEs
- **Configuration Scanning**: Finds misconfigurations like debug mode, default passwords, exposed ports
- **CVSS v3 Scoring**: Computes severity scores for discovered vulnerabilities
- **Fix Suggestions**: Generates actionable code fix recommendations
- **Vulnerability Prioritization**: Ranks findings by exploitability and impact
- **Rich Reports**: Produces formatted console and JSON reports

## Installation

```bash
pip install -e .
```

## Usage

### Scan a file or directory for code vulnerabilities

```bash
vulnfix scan code path/to/source
```

### Check dependencies for known CVEs

```bash
vulnfix scan deps requirements.txt
```

### Scan configuration files for misconfigurations

```bash
vulnfix scan config path/to/config
```

### Full scan (code + deps + config)

```bash
vulnfix scan all path/to/project
```

### Generate a report

```bash
vulnfix report path/to/project --format json --output report.json
```

## Development

```bash
pip install -e ".[dev]"
pytest
```

## Author

Mukunda Katta

## License

MIT

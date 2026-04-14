# vulnfix — AI Vulnerability Scanner. Automated security vulnerability detection and fix suggestions

AI Vulnerability Scanner. Automated security vulnerability detection and fix suggestions. vulnfix gives you a focused, inspectable implementation of that idea.

## Why vulnfix

vulnfix exists to make this workflow practical. Ai vulnerability scanner. automated security vulnerability detection and fix suggestions. It favours a small, inspectable surface over sprawling configuration.

## Features

- CLI command `vulnfix`
- Included test suite
- Worked examples included

## Tech Stack

- **Runtime:** Python
- **Frameworks:** Click
- **Tooling:** pytest, Pydantic, Rich

## How It Works

The codebase is organised into `examples/`, `src/`, `tests/`. The primary entry points are `src/vulnfix/cli.py`, `src/vulnfix/__init__.py`. `src/vulnfix/cli.py` exposes functions like `_run_scan`, `cli`.

## Getting Started

```bash
pip install -e .
vulnfix --help
```

## Usage

```bash
vulnfix --help
```

## Project Structure

```
vulnfix/
├── .env.example
├── CONTRIBUTING.md
├── README.md
├── config.example.yaml
├── examples/
├── index.html
├── pyproject.toml
├── requirements.txt
├── src/
├── tests/
```

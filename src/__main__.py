"""CLI for vulnfix."""
import sys, json, argparse
from .core import Vulnfix

def main():
    parser = argparse.ArgumentParser(description="VulnFix — AI Vulnerability Scanner. Automated security vulnerability detection and fix suggestions.")
    parser.add_argument("command", nargs="?", default="status", choices=["status", "run", "info"])
    parser.add_argument("--input", "-i", default="")
    args = parser.parse_args()
    instance = Vulnfix()
    if args.command == "status":
        print(json.dumps(instance.get_stats(), indent=2))
    elif args.command == "run":
        print(json.dumps(instance.detect(input=args.input or "test"), indent=2, default=str))
    elif args.command == "info":
        print(f"vulnfix v0.1.0 — VulnFix — AI Vulnerability Scanner. Automated security vulnerability detection and fix suggestions.")

if __name__ == "__main__":
    main()

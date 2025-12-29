"""Command-line entry point for phishing analysis."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .analyzer import analyze_email, analyze_url


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Phishing analysis & detection toolkit")
    parser.add_argument("--url", help="URL to analyze")
    parser.add_argument("--email-file", help="Path to raw email file")
    parser.add_argument(
        "--output",
        choices=["text", "json"],
        default="text",
        help="Output format",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if not args.url and not args.email_file:
        parser.error("Provide --url or --email-file")

    results = []
    if args.url:
        results.append(analyze_url(args.url))

    if args.email_file:
        raw_email = Path(args.email_file).read_text(encoding="utf-8")
        results.append(analyze_email(raw_email))

    if args.output == "json":
        payload = [
            {
                "target": result.target,
                "score": result.score,
                "verdict": result.verdict,
                "findings": [finding.__dict__ for finding in result.findings],
            }
            for result in results
        ]
        print(json.dumps(payload, indent=2))
        return

    for result in results:
        print(f"Target: {result.target}")
        print(f"Score: {result.score}")
        print(f"Verdict: {result.verdict}")
        if result.findings:
            print("Findings:")
            for finding in result.findings:
                print(f" - [{finding.severity}] {finding.label}: {finding.detail}")
        else:
            print("Findings: none")
        print()


if __name__ == "__main__":
    main()

"""Command-line entry point for phishing analysis."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .analyzer import analyze_email, analyze_url
from .port_scanner import parse_ports, scan_ports


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Phishing analysis & detection toolkit")
    parser.add_argument("--url", help="URL to analyze")
    parser.add_argument("--email-file", help="Path to raw email file")
    parser.add_argument("--scan-host", help="Host to run a basic TCP port scan")
    parser.add_argument(
        "--ports",
        default="22,80,443",
        help="Comma-separated ports or ranges (e.g. 22,80,443,8000-8100)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=0.5,
        help="Connection timeout per port in seconds",
    )
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

    if not args.url and not args.email_file and not args.scan_host:
        parser.error("Provide --url, --email-file, or --scan-host")

    analysis_results = []
    port_scan_results = []
    if args.url:
        analysis_results.append(analyze_url(args.url))

    if args.email_file:
        raw_email = Path(args.email_file).read_text(encoding="utf-8")
        analysis_results.append(analyze_email(raw_email))

    if args.scan_host:
        try:
            ports = parse_ports(args.ports)
        except ValueError as exc:
            parser.error(str(exc))
        port_scan_results.append(scan_ports(args.scan_host, ports, args.timeout))

    if args.output == "json":
        payload = {
            "phishing_results": [
                {
                    "target": result.target,
                    "score": result.score,
                    "verdict": result.verdict,
                    "findings": [finding.__dict__ for finding in result.findings],
                }
                for result in analysis_results
            ],
            "port_scans": [
                {
                    "host": scan.host,
                    "timeout": scan.timeout,
                    "open_ports": scan.open_ports,
                    "closed_ports": scan.closed_ports,
                }
                for scan in port_scan_results
            ],
        }
        print(json.dumps(payload, indent=2))
        return

    for result in analysis_results:
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

    for scan in port_scan_results:
        open_ports = ", ".join(str(port) for port in scan.open_ports) or "none"
        closed_ports = ", ".join(str(port) for port in scan.closed_ports) or "none"
        print(f"Port scan host: {scan.host}")
        print(f"Timeout: {scan.timeout:.2f}s")
        print(f"Open ports: {open_ports}")
        print(f"Closed ports: {closed_ports}")
        print()


if __name__ == "__main__":
    main()

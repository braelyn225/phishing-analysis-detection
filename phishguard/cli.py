from __future__ import annotations

import argparse
from pathlib import Path

from rich.console import Console
from rich.table import Table

from .indicators import contains_urgency, extract_iocs, has_punycode, has_suspicious_tld, url_uses_ip
from .parser_eml import extract_body_text, get_header, load_eml
from .report import findings_to_dict, write_json, write_markdown
from .scoring import Finding, score_findings

console = Console()


def analyze_eml(path: str) -> dict:
    msg = load_eml(path)

    hdr_from = get_header(msg, "From")
    hdr_reply_to = get_header(msg, "Reply-To")
    hdr_subject = get_header(msg, "Subject")
    hdr_date = get_header(msg, "Date")
    auth_results = get_header(msg, "Authentication-Results")

    body = extract_body_text(msg)
    iocs = extract_iocs("\n".join([hdr_subject, hdr_from, hdr_reply_to, auth_results, body]))

    findings: list[Finding] = []

    # Heuristics
    if hdr_reply_to and hdr_from and (hdr_reply_to.lower() not in hdr_from.lower()):
        findings.append(
            Finding(
                name="Reply-To mismatch",
                weight=25,
                detail=f"Reply-To differs from From ({hdr_reply_to} vs {hdr_from})",
            )
        )

    if has_punycode(iocs.domains):
        findings.append(
            Finding(
                name="Punycode domain detected",
                weight=25,
                detail="One or more domains include 'xn--' (possible homograph attack).",
            )
        )

    if has_suspicious_tld(iocs.domains):
        findings.append(
            Finding(
                name="Suspicious TLD detected",
                weight=15,
                detail="One or more domains use a commonly abused TLD.",
            )
        )

    if url_uses_ip(iocs.urls):
        findings.append(
            Finding(
                name="URL contains IP address",
                weight=20,
                detail="At least one URL uses a raw IP instead of a domain.",
            )
        )

    urgency_hits = contains_urgency(body + " " + hdr_subject)
    if urgency_hits:
        findings.append(
            Finding(
                name="Urgency / credential bait language",
                weight=10,
                detail=f"Detected keywords: {', '.join(urgency_hits[:6])}",
            )
        )

    # SPF/DKIM/DMARC hinting (best-effort based on Authentication-Results header)
    ar = auth_results.lower()
    if auth_results:
        if "spf=fail" in ar or "spf=softfail" in ar:
            findings.append(
                Finding("SPF failed", 30, "Authentication-Results indicates SPF did not pass.")
            )
        if "dkim=fail" in ar:
            findings.append(
                Finding("DKIM failed", 30, "Authentication-Results indicates DKIM did not pass.")
            )
        if "dmarc=fail" in ar:
            findings.append(
                Finding("DMARC failed", 30, "Authentication-Results indicates DMARC did not pass.")
            )

    score, label = score_findings(findings)

    return {
        "email": {
            "path": str(Path(path).resolve()),
            "subject": hdr_subject,
            "from": hdr_from,
            "reply_to": hdr_reply_to,
            "date": hdr_date,
            "authentication_results": auth_results,
        },
        "iocs": {
            "urls": iocs.urls,
            "domains": iocs.domains,
            "ips": iocs.ips,
            "hashes": iocs.hashes,
        },
        "findings": findings_to_dict(findings),
        "risk_score": score,
        "risk_label": label,
    }


def print_console_summary(report: dict) -> None:
    table = Table(title="PhishGuard Summary")
    table.add_column("Field")
    table.add_column("Value", overflow="fold")

    e = report["email"]
    table.add_row("Subject", e["subject"])
    table.add_row("From", e["from"])
    table.add_row("Reply-To", e["reply_to"])
    table.add_row("Risk", f"{report['risk_label']} ({report['risk_score']})")

    console.print(table)

    if report["findings"]:
        ftable = Table(title="Findings")
        ftable.add_column("Name")
        ftable.add_column("Weight")
        ftable.add_column("Detail", overflow="fold")
        for f in report["findings"]:
            ftable.add_row(f["name"], str(f["weight"]), f["detail"])
        console.print(ftable)


def main() -> None:
    ap = argparse.ArgumentParser(
        prog="phishguard", description="Analyze .eml files for phishing indicators + IOCs."
    )
    ap.add_argument("eml", help="Path to .eml file")
    ap.add_argument("-o", "--outdir", default="out", help="Output directory (default: out)")
    args = ap.parse_args()

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    report = analyze_eml(args.eml)
    write_json(outdir / "report.json", report)
    write_markdown(outdir / "report.md", report)

    print_console_summary(report)
    console.print(f"\nWrote: {outdir/'report.json'}")
    console.print(f"Wrote: {outdir/'report.md'}")


if __name__ == "__main__":
    main()

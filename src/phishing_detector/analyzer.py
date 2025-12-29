"""Core analysis logic for phishing detection."""

from __future__ import annotations

import re
from dataclasses import dataclass
from email import message_from_string
from email.message import Message
from typing import Iterable
from urllib.parse import urlparse

SUSPICIOUS_TLDS = {"zip", "mov", "top", "xyz", "gq", "work"}
SUSPICIOUS_KEYWORDS = {
    "login",
    "verify",
    "update",
    "password",
    "secure",
    "account",
    "invoice",
    "bank",
    "payment",
}


@dataclass
class Finding:
    label: str
    detail: str
    severity: str = "medium"


@dataclass
class AnalysisResult:
    target: str
    score: int
    findings: list[Finding]

    @property
    def verdict(self) -> str:
        if self.score >= 6:
            return "high risk"
        if self.score >= 3:
            return "suspicious"
        return "low risk"


def analyze_url(url: str) -> AnalysisResult:
    findings: list[Finding] = []
    score = 0

    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    if parsed.scheme not in {"http", "https"}:
        findings.append(Finding("scheme", "Unusual URL scheme", "medium"))
        score += 2

    if _looks_like_ip(hostname):
        findings.append(Finding("ip_address", "Hostname is an IP address", "high"))
        score += 3

    if "@" in url:
        findings.append(Finding("at_symbol", "URL contains '@'", "high"))
        score += 3

    if len(url) > 75:
        findings.append(Finding("length", "URL length is unusually long", "medium"))
        score += 2

    subdomain_count = hostname.count(".")
    if subdomain_count >= 3:
        findings.append(Finding("subdomain", "Many subdomains detected", "medium"))
        score += 2

    if "-" in hostname:
        findings.append(Finding("hyphen", "Hyphenated hostname", "low"))
        score += 1

    tld = hostname.rsplit(".", 1)[-1].lower() if "." in hostname else ""
    if tld in SUSPICIOUS_TLDS:
        findings.append(Finding("tld", f"Suspicious TLD '.{tld}'", "high"))
        score += 3

    keyword_hits = _keyword_hits([hostname, path, query])
    if keyword_hits:
        findings.append(
            Finding(
                "keywords",
                f"Sensitive keywords found: {', '.join(sorted(keyword_hits))}",
                "medium",
            )
        )
        score += 2

    if parsed.scheme == "http":
        findings.append(Finding("unencrypted", "URL uses HTTP instead of HTTPS", "medium"))
        score += 1

    return AnalysisResult(target=url, score=score, findings=findings)


def analyze_email(raw_email: str) -> AnalysisResult:
    message = message_from_string(raw_email)
    score = 0
    findings: list[Finding] = []

    sender = _header_value(message, "From")
    reply_to = _header_value(message, "Reply-To")
    subject = _header_value(message, "Subject")

    if reply_to and sender and reply_to.lower() != sender.lower():
        findings.append(
            Finding("reply_to", "Reply-To header differs from sender", "high")
        )
        score += 3

    subject_keywords = _keyword_hits([subject])
    if subject_keywords:
        findings.append(
            Finding(
                "subject_keywords",
                f"Sensitive keywords in subject: {', '.join(sorted(subject_keywords))}",
                "medium",
            )
        )
        score += 2

    body = _extract_body(message)
    urls = _extract_urls(body)
    if urls:
        findings.append(Finding("urls", f"Email contains {len(urls)} URL(s)", "low"))
        score += 1

    risky_urls = []
    for url in urls:
        url_result = analyze_url(url)
        if url_result.score >= 3:
            risky_urls.append(url)
            score += min(url_result.score, 4)

    if risky_urls:
        findings.append(
            Finding(
                "risky_urls",
                "High-risk URL(s): " + ", ".join(risky_urls),
                "high",
            )
        )

    if _looks_like_urgent_request(body):
        findings.append(
            Finding("urgency", "Urgent language detected in body", "medium")
        )
        score += 2

    return AnalysisResult(target=sender or "email", score=score, findings=findings)


def _header_value(message: Message, header: str) -> str:
    value = message.get(header, "")
    return value.strip()


def _extract_body(message: Message) -> str:
    if message.is_multipart():
        parts = []
        for part in message.walk():
            if part.get_content_type() == "text/plain":
                payload = part.get_payload(decode=True) or b""
                charset = part.get_content_charset() or "utf-8"
                parts.append(payload.decode(charset, errors="replace"))
        return "\n".join(parts)
    payload = message.get_payload(decode=True) or b""
    charset = message.get_content_charset() or "utf-8"
    return payload.decode(charset, errors="replace")


def _extract_urls(text: str) -> list[str]:
    return re.findall(r"https?://[^\s)]+", text)


def _keyword_hits(parts: Iterable[str]) -> set[str]:
    hits = set()
    for part in parts:
        lowered = part.lower()
        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in lowered:
                hits.add(keyword)
    return hits


def _looks_like_ip(hostname: str) -> bool:
    return bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", hostname))


def _looks_like_urgent_request(text: str) -> bool:
    patterns = [
        "urgent",
        "immediately",
        "action required",
        "verify your account",
        "suspend",
    ]
    lowered = text.lower()
    return any(pattern in lowered for pattern in patterns)

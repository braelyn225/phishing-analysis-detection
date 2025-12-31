"""Core analysis logic for phishing detection."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from email import message_from_string
from email.header import decode_header, make_header
from email.message import Message
from email.utils import parseaddr
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
    sender_address = _normalized_address(sender)
    reply_to_address = _normalized_address(reply_to)

    if reply_to_address and sender_address and reply_to_address != sender_address:
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
    highest_url_score = 0
    for url in urls:
        url_result = analyze_url(url)
        highest_url_score = max(highest_url_score, min(url_result.score, 4))
        if url_result.score >= 3:
            risky_urls.append(_defang_url(url))

    if highest_url_score:
        score += highest_url_score

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
    return str(make_header(decode_header(value))).strip()


def _normalized_address(value: str) -> str:
    _, address = parseaddr(value)
    return address.strip().lower()


def _extract_body(message: Message) -> str:
    if message.is_multipart():
        plain_parts = []
        html_parts = []
        for part in message.walk():
            payload = part.get_payload(decode=True) or b""
            charset = part.get_content_charset() or "utf-8"
            if part.get_content_type() == "text/plain":
                plain_parts.append(payload.decode(charset, errors="replace"))
            elif part.get_content_type() == "text/html":
                html_parts.append(payload.decode(charset, errors="replace"))
        if plain_parts:
            return "\n".join(plain_parts)
        if html_parts:
            return _strip_html("\n".join(html_parts))
        return ""
    payload = message.get_payload(decode=True) or b""
    charset = message.get_content_charset() or "utf-8"
    decoded = payload.decode(charset, errors="replace")
    if message.get_content_type() == "text/html":
        return _strip_html(decoded)
    return decoded


def _extract_urls(text: str) -> list[str]:
    candidates = re.findall(
        r"(?:hxxps?://|https?://|www\.)[^\s<>()]+",
        text,
        flags=re.IGNORECASE,
    )
    urls = []
    for candidate in candidates:
        cleaned = _strip_url_punctuation(candidate)
        normalized = _normalize_url(cleaned)
        if normalized:
            urls.append(normalized)
    return urls


def _keyword_hits(parts: Iterable[str]) -> set[str]:
    hits = set()
    for part in parts:
        lowered = part.lower()
        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in lowered:
                hits.add(keyword)
    return hits


def _looks_like_ip(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        return False
    return True


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


def _strip_html(html: str) -> str:
    text = re.sub(r"<script.*?>.*?</script>", " ", html, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r"<style.*?>.*?</style>", " ", text, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r"<[^>]+>", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def _strip_url_punctuation(candidate: str) -> str:
    return candidate.strip(".,;:!?)\"]}'")


def _normalize_url(candidate: str) -> str | None:
    defanged = _refang_url(candidate)
    if defanged.lower().startswith("www."):
        defanged = f"http://{defanged}"
    parsed = urlparse(defanged)
    if not parsed.scheme and defanged.lower().startswith("http"):
        return defanged
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        return defanged
    return None


def _refang_url(url: str) -> str:
    updated = re.sub(r"^hxxps", "https", url, flags=re.IGNORECASE)
    updated = re.sub(r"^hxxp", "http", updated, flags=re.IGNORECASE)
    updated = updated.replace("[.]", ".").replace("(.)", ".")
    return updated


def _defang_url(url: str) -> str:
    updated = re.sub(r"^https", "hxxps", url, flags=re.IGNORECASE)
    updated = re.sub(r"^http", "hxxp", updated, flags=re.IGNORECASE)
    return updated.replace(".", "[.]")

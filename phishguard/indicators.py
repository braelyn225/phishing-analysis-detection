from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

from .utils import deobfuscate, safe_domain_from_url


URL_RE = re.compile(r"\bhttps?://[^\s<>()\"\']+", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b")
HASH_RE = re.compile(r"\b([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b")
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")

SUSPICIOUS_TLDS = {
    "zip",
    "mov",
    "top",
    "xyz",
    "click",
    "ru",
    "tk",
    "gq",
    "cf",
    "ml",
    "work",
    "cam",
}

URGENCY_KEYWORDS = [
    "urgent",
    "immediately",
    "verify",
    "password",
    "account locked",
    "action required",
    "suspended",
    "invoice",
    "wire",
    "gift card",
]


@dataclass
class IOCResult:
    urls: list[str]
    domains: list[str]
    ips: list[str]
    hashes: list[str]


def extract_iocs(text: str) -> IOCResult:
    t = deobfuscate(text)

    urls = sorted(set(URL_RE.findall(t)))
    ips = sorted(set(IP_RE.findall(t)))
    hashes = sorted(set(m.group(1) for m in HASH_RE.finditer(t)))

    domains = set()
    # from URLs
    for u in urls:
        d = safe_domain_from_url(u)
        if d:
            domains.add(d)
    # also find standalone domains
    for d in DOMAIN_RE.findall(t):
        domains.add(d.lower())

    return IOCResult(urls=urls, domains=sorted(domains), ips=ips, hashes=hashes)


def has_punycode(domains: Iterable[str]) -> bool:
    return any("xn--" in d for d in domains)


def has_suspicious_tld(domains: Iterable[str]) -> bool:
    for d in domains:
        tld = d.rsplit(".", 1)[-1].lower()
        if tld in SUSPICIOUS_TLDS:
            return True
    return False


def url_uses_ip(urls: Iterable[str]) -> bool:
    for u in urls:
        if IP_RE.search(u):
            return True
    return False


def contains_urgency(text: str) -> list[str]:
    t = text.lower()
    hits = [k for k in URGENCY_KEYWORDS if k in t]
    return hits

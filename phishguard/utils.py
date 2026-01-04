from __future__ import annotations

import re
from urllib.parse import urlparse


HXXP_RE = re.compile(r"\bhxxps?://", re.IGNORECASE)


def deobfuscate(text: str) -> str:
    # Common analyst deobfuscations
    t = text
    t = HXXP_RE.sub(lambda m: "https://" if "hxxps" in m.group(0).lower() else "http://", t)
    t = t.replace("[.]", ".").replace("(.)", ".")
    return t


def safe_domain_from_url(url: str) -> str | None:
    try:
        p = urlparse(url)
        host = p.hostname
        if not host:
            return None
        return host.lower()
    except Exception:
        return None
